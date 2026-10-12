#!/usr/bin/env python3
"""
dga_detect.py (v2) - Generic suspicious-domain hunter for Zeek dns.log.

Nothing is hardcoded to specific domains or IPs. Each queried name is split into
(subdomain, second-level label, suffix) and scored from independent evidence
signals; the report shows WHY a name was flagged and which IPs it resolved to.

  Lexical signals (second-level label)
    entropy, English-bigram plausibility, vowel ratio, consonant runs, digits,
    hex/base32 labels, and "syllabic" labels (perfect consonant/vowel alternation,
    e.g. pronounceable generated names that fool plain entropy checks).
  Behavioural signals
    rare            queried only once or twice in the capture
    direct-A        resolves straight to 1-2 IPs with no CNAME hop to another
                    registered domain (big legit services sit behind CDN chains)
    nxdomain        random-looking name that failed to resolve / never resolves
    ip-lookup       external-IP discovery services (recon step before C2);
                    keyword category, extendable with --recon-file
  Optional, with --conn conn.log (strongly recommended)
    beaconing-ip    the resolved IP is contacted with regular timing afterwards
    big-download    rare + direct-A domain followed by a large download
  Host / tunnelling
    per-host NXDOMAIN volume and DGA-like count; many random subdomains under
    one parent => DNS tunnelling.

Usage:
    python3 dga_detect.py dns.log
    python3 dga_detect.py dns.log --conn conn.log --top 25 --csv out.csv
    python3 dga_detect.py dns.log --allowlist known_good.txt
    python3 dga_detect.py --test x9k2m8q7z1p4.com google.com
"""
import argparse
import csv
import json
import math
import re
import statistics as st
import sys
from collections import Counter, defaultdict

# ---------------------------------------------------------------- constants
COMMON_BIGRAMS = set("""
th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as
ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la
ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh
ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai sh ir su id os iv ia am fi
ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay ex ke fr oo av ag if ap gr
od bo sp rd do uc bu ei ov by rm ep tt ok ew up ob ub ck ft oc ke ik ak ib
""".split())

VOWELS = set("aeiou")
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne"}
NOISE_SUFFIXES = (".arpa", ".local", ".lan", ".home", ".internal", ".localdomain",
                  ".corp", ".intranet")
HEX_RE = re.compile(r"^[0-9a-f]{12,}$")
B32_RE = re.compile(r"^[a-z2-7]{20,}$")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Category: "what is my external IP" services. Attackers use them to learn the
# victim's public address (MITRE T1016 / T1590.005). On its own this is NOT proof
# of malice - it is a context indicator. Extend with --recon-file.
RECON_KEYWORDS = [
    "whatismyip", "whatsmyip", "myexternalip", "myip", "getmyip", "showmyip", "checkip",
    "icanhazip", "ipify", "ifconfig", "ipinfo", "ip-api", "ipecho", "wtfismyip",
    "externalip", "publicip", "ipchicken", "ident.me", "ipapi", "ipwho", "ip.sb",
]


# ---------------------------------------------------------------- parsing
def parse_zeek(path):
    fields, sep, unset = None, "\t", "-"
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line:
                continue
            if line.startswith("#"):
                if line.startswith("#separator"):
                    tok = line.split(" ", 1)[1].strip()
                    sep = bytes(tok, "utf-8").decode("unicode_escape") if tok.startswith("\\x") else tok
                elif line.startswith("#fields"):
                    fields = line.split(sep)[1:]
                continue
            if line.lstrip().startswith("{"):
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass
                continue
            if fields is None:
                continue
            parts = line.split(sep)
            if len(parts) >= len(fields):
                yield {k: (None if v == unset else v) for k, v in zip(fields, parts)}


def num(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def split_name(name):
    """-> (subdomain, sld, suffix). Light public-suffix heuristic, no external deps."""
    labels = name.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return "", labels[0], ""
    tld = labels[-1]
    if len(labels) >= 3 and len(tld) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[:-3]), labels[-3], ".".join(labels[-2:])
    return ".".join(labels[:-2]), labels[-2], tld


def parent_of(name):
    sub, sld, suffix = split_name(name)
    return f"{sld}.{suffix}" if suffix else sld


def is_noise(name):
    n = name.lower().rstrip(".")
    if not n or "." not in n:
        return True
    if n.endswith(NOISE_SUFFIXES) or n.startswith("_") or "._" in n:
        return True
    if re.fullmatch(r"[0-9.]+", n):
        return True
    return False


def is_private(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_private or a.is_multicast or a.is_loopback or a.is_link_local or a.is_reserved


# ---------------------------------------------------------------- lexical features
def shannon(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def bigram_hit_ratio(s):
    letters = re.sub(r"[^a-z]", "", s)
    if len(letters) < 3:
        return 1.0
    pairs = [letters[i:i + 2] for i in range(len(letters) - 1)]
    return sum(p in COMMON_BIGRAMS for p in pairs) / len(pairs)


def longest_consonant_run(s):
    best = cur = 0
    for ch in s:
        if ch.isalpha() and ch not in VOWELS and ch != "y":
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def cv_alternation(core):
    """Fraction of adjacent letter pairs that switch consonant<->vowel (y = consonant)."""
    s = re.sub(r"[^a-z]", "", core)
    if len(s) < 2:
        return 0.0
    kinds = [c in VOWELS for c in s]
    return sum(kinds[i] != kinds[i + 1] for i in range(len(kinds) - 1)) / (len(kinds) - 1)


def lexical_features(label):
    core = label.replace("-", "")
    n = len(core)
    letters = [c for c in core if c.isalpha()]
    vowel_ratio = (sum(c in VOWELS for c in letters) / len(letters)) if letters else 0.0
    return {
        "len": n,
        "entropy": shannon(core),
        "digit_ratio": sum(c.isdigit() for c in core) / n if n else 0.0,
        "vowel_ratio": vowel_ratio,
        "bigram_hit": bigram_hit_ratio(core),
        "cons_run": longest_consonant_run(core),
        "cv_alt": cv_alternation(core),
        "hex_like": bool(HEX_RE.match(core)),
        "b32_like": bool(B32_RE.match(core)),
    }


def lexical_score(f):
    n = f["len"]
    if n < 6:
        return 0.0
    max_h = math.log2(min(n, 36))
    s_ent = clamp(((f["entropy"] / max_h) - 0.80) / 0.20) if max_h else 0.0
    s_ent *= clamp((n - 6) / 6)
    s_big = clamp((0.70 - f["bigram_hit"]) / 0.45)
    s_vow = clamp(abs(f["vowel_ratio"] - 0.38) / 0.20)
    s_run = clamp((f["cons_run"] - 3) / 4)
    s_dig = clamp(f["digit_ratio"] / 0.35)
    s_len = clamp((n - 10) / 14)
    score = 100 * (0.25 * s_ent + 0.30 * s_big + 0.15 * s_vow +
                   0.10 * s_run + 0.10 * s_dig + 0.10 * s_len)
    if f["hex_like"] or f["b32_like"]:
        score = max(score, 70.0)
    return min(100.0, score)


def syllabic_score(f):
    """Pronounceable-but-generated labels: strict C/V alternation, 8+ letters,
    plausible vowel share. 0..1."""
    if f["len"] < 8 or not (0.30 <= f["vowel_ratio"] <= 0.65):
        return 0.0
    return clamp((f["cv_alt"] - 0.85) / 0.15) * clamp((f["len"] - 7) / 3)


def level(score):
    return "HIGH" if score >= 70 else "MEDIUM" if score >= 45 else "LOW"


# ---------------------------------------------------------------- conn.log correlation
def load_conn_index(path):
    """external resp IP -> {'times': [...], 'resp_bytes': total}"""
    idx = defaultdict(lambda: {"times": [], "resp_bytes": 0.0})
    for row in parse_zeek(path):
        dst = row.get("id.resp_h")
        if not dst or is_private(dst):
            continue
        rec = idx[dst]
        rec["times"].append(num(row.get("ts")))
        rec["resp_bytes"] += num(row.get("resp_bytes"))
    return idx


def channel_regularity(times, min_conns=8):
    """0..100: how timer-like the contacts with one IP are (compact version of
    the beacon_detect.py logic: robust jitter + on-period share + persistence)."""
    times = sorted(times)
    dedup = [times[0]] if times else []
    for t in times[1:]:
        if t - dedup[-1] > 0.5:
            dedup.append(t)
    if len(dedup) < min_conns:
        return 0.0
    iv = [b - a for a, b in zip(dedup, dedup[1:])]
    med = st.median(iv)
    if med <= 0:
        return 0.0
    mad = st.median(abs(x - med) for x in iv)
    jitter = clamp(1.4826 * mad / med)
    frac = sum(1 for x in iv if abs(x - med) <= 0.25 * med) / len(iv)
    cnt = clamp(math.log2(len(dedup)) / math.log2(40))
    return 100 * (0.4 * (1 - jitter) + 0.3 * frac + 0.3 * cnt)


# ---------------------------------------------------------------- analysis
def answers_list(raw):
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x) for x in raw]
    return [a for a in str(raw).split(",") if a]


def analyse(queries, args, conn_idx=None, recon_words=None, allow=None):
    recon_words = recon_words or RECON_KEYWORDS
    per = {}
    host_names = defaultdict(set)
    host_nx, host_total = Counter(), Counter()
    sld_subs = defaultdict(set)

    for q in queries:
        name = q["name"].lower().rstrip(".")
        parent = parent_of(name)
        if allow and any(parent == a or parent.endswith("." + a) for a in allow):
            continue
        sub, sld, _ = split_name(name)
        host_total[q["host"]] += 1
        if sub:
            sld_subs[parent].add(sub)
        r = per.setdefault(parent, {"sld": sld, "queries": 0, "nx": 0, "hosts": set(),
                                    "ips": [], "indirect": False, "full_names": set(),
                                    "first_ts": q["ts"]})
        r["queries"] += 1
        r["hosts"].add(q["host"])
        r["full_names"].add(name)
        r["first_ts"] = min(r["first_ts"], q["ts"])
        if q["nx"]:
            r["nx"] += 1
            host_nx[q["host"]] += 1
        for a in q["answers"]:
            if IPV4_RE.match(a) or ":" in a:
                if a not in r["ips"]:
                    r["ips"].append(a)
            elif parent_of(a) != parent:
                r["indirect"] = True            # CNAME hop to another registered domain
        host_names[q["host"]].add(parent)

    domains = []
    for d, r in per.items():
        f = lexical_features(r["sld"])
        lex = lexical_score(f)
        score, why = lex, []
        if lex >= 45:
            why.append("random-lexical")

        syl = syllabic_score(f)
        if syl >= 0.5:
            score += 22 * syl
            why.append("syllabic-generated")

        rare = r["queries"] <= 2
        direct = bool(r["ips"]) and len(r["ips"]) <= 2 and not r["indirect"]
        if rare and direct:
            score += 12
            why.append("rare+direct-A")

        if r["nx"] and lex >= 30:
            score += 15
            why.append("random+NXDOMAIN")
        elif r["queries"] >= 3 and r["nx"] == r["queries"] and lex >= 20:
            score += 10
            why.append("never-resolves")

        if any(w in n for n in r["full_names"] for w in recon_words):
            score += 20
            why.append("ip-lookup-service")

        beacon = 0.0
        dl_bytes = 0.0
        if conn_idx:
            for ip in r["ips"]:
                c = conn_idx.get(ip)
                if c:
                    beacon = max(beacon, channel_regularity(c["times"]))
                    dl_bytes = max(dl_bytes, c["resp_bytes"])
            if beacon >= 60:
                score += 0.4 * beacon
                why.append(f"beaconing-ip({beacon:.0f})")
            if rare and direct and dl_bytes >= 50_000:
                score += 15
                why.append("big-download")

        score = min(100.0, score)
        domains.append({
            "domain": d, "score": round(score, 1), "level": level(score),
            "ips": ",".join(r["ips"][:3]) + ("…" if len(r["ips"]) > 3 else ""),
            "queries": r["queries"], "nxdomain": r["nx"], "hosts": len(r["hosts"]),
            "why": " ".join(why) or "-",
            "lexical": round(lex, 1), "entropy": round(f["entropy"], 2), "len": f["len"],
            "bigram_hit_pct": round(100 * f["bigram_hit"]), "vowel_pct": round(100 * f["vowel_ratio"]),
            "cv_alt_pct": round(100 * f["cv_alt"]), "cons_run": f["cons_run"],
            "first_seen": r["first_ts"],
        })
    domains.sort(key=lambda x: (x["score"], x["nxdomain"]), reverse=True)
    score_of = {d["domain"]: d["score"] for d in domains}

    hosts = []
    for h, names in host_names.items():
        sus = [n for n in names if score_of.get(n, 0) >= args.threshold]
        nx = host_nx[h]
        ratio = nx / host_total[h] if host_total[h] else 0.0
        hs = 40 * clamp(len(sus) / 10) + 35 * clamp(nx / 30) + 25 * clamp(ratio / 0.5)
        hosts.append({"host": h, "score": round(hs, 1), "level": level(hs),
                      "queries": host_total[h], "unique_domains": len(names),
                      "flagged_domains": len(sus), "nxdomain": nx,
                      "nx_ratio_pct": round(100 * ratio)})
    hosts.sort(key=lambda x: x["score"], reverse=True)

    tunnels = []
    for parent, subs in sld_subs.items():
        if len(subs) < args.tunnel_min_subs:
            continue
        ents = [shannon(s.replace(".", "")) for s in subs]
        lens = [len(s) for s in subs]
        ae, al = sum(ents) / len(ents), sum(lens) / len(lens)
        if ae >= 3.0 and al >= 16:
            tunnels.append({"parent": parent, "distinct_subdomains": len(subs),
                            "avg_entropy": round(ae, 2), "avg_len": round(al, 1)})
    tunnels.sort(key=lambda x: x["distinct_subdomains"], reverse=True)
    return domains, hosts, tunnels


# ---------------------------------------------------------------- main
def load_queries(path):
    out = []
    for row in parse_zeek(path):
        name = row.get("query")
        if not name or is_noise(name):
            continue
        qtype = (row.get("qtype_name") or "").upper()
        if qtype in ("PTR", "SRV", "NB", "NBSTAT", "NIMLOC"):
            continue
        out.append({"ts": num(row.get("ts")), "host": row.get("id.orig_h") or "?", "name": name,
                    "nx": (row.get("rcode_name") or "").upper() == "NXDOMAIN",
                    "answers": answers_list(row.get("answers"))})
    return out


def table(rows, cols, head):
    print(head)
    if not rows:
        print("  (none)\n")
        return
    w = [max(len(c), *(len(str(r[c])) for r in rows)) for c in cols]
    print("  " + "  ".join(c.upper().ljust(x) for c, x in zip(cols, w)))
    print("  " + "  ".join("-" * x for x in w))
    for r in rows:
        print("  " + "  ".join(str(r[c]).ljust(x) for c, x in zip(cols, w)))
    print()


def read_lines(path):
    with open(path) as f:
        return [l.strip().lower() for l in f if l.strip() and not l.startswith("#")]


def main():
    ap = argparse.ArgumentParser(description="Generic suspicious-domain hunter for Zeek dns.log")
    ap.add_argument("logfile", nargs="?", help="Zeek dns.log (TSV or JSON)")
    ap.add_argument("--conn", help="Zeek conn.log: adds beaconing / download correlation for resolved IPs")
    ap.add_argument("--test", nargs="+", metavar="DOMAIN", help="score domains given on the command line")
    ap.add_argument("--allowlist", help="file with known-good parent domains to ignore (one per line)")
    ap.add_argument("--recon-file", help="extra IP-lookup keywords, one per line")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--threshold", type=float, default=45.0, help="score counted as flagged in host summary")
    ap.add_argument("--tunnel-min-subs", type=int, default=15)
    ap.add_argument("--csv")
    ap.add_argument("--json")
    args = ap.parse_args()

    if args.test:
        queries = [{"ts": 0.0, "host": "cli", "name": d, "nx": False, "answers": []}
                   for d in args.test if not is_noise(d)]
    elif args.logfile:
        queries = load_queries(args.logfile)
    else:
        ap.error("give a dns.log path or --test DOMAIN [DOMAIN ...]")

    conn_idx = load_conn_index(args.conn) if args.conn else None
    recon = RECON_KEYWORDS + (read_lines(args.recon_file) if args.recon_file else [])
    allow = read_lines(args.allowlist) if args.allowlist else None

    domains, hosts, tunnels = analyse(queries, args, conn_idx, recon, allow)
    print(f"[*] {len(queries)} DNS queries, {len(domains)} unique registered domains"
          f"{'' if conn_idx else '  (no --conn: beaconing correlation disabled)'}\n")
    table(domains[: args.top], ["domain", "score", "level", "ips", "queries", "nxdomain", "why"],
          "== Domains ranked by suspicion ==")
    if not args.test:
        table(hosts[:10], ["host", "score", "level", "queries", "unique_domains",
                           "flagged_domains", "nxdomain", "nx_ratio_pct"], "== Hosts (behaviour) ==")
        table(tunnels[:10], ["parent", "distinct_subdomains", "avg_entropy", "avg_len"],
              "== Possible DNS tunnelling (many random-looking subdomains) ==")

    if args.csv and domains:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(domains[0].keys()))
            w.writeheader()
            w.writerows(domains)
        print(f"[+] CSV written: {args.csv}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"domains": domains, "hosts": hosts, "tunnels": tunnels}, f, indent=2)
        print(f"[+] JSON written: {args.json}")


if __name__ == "__main__":
    sys.exit(main())
