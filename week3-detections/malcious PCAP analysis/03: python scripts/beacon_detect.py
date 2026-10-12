#!/usr/bin/env python3
"""
beacon_detect.py - Generic beaconing detector for Zeek conn.log (TSV or JSON).

No IPs, ports or domains are hardcoded. Every (src, dst, dport, proto) channel
is scored purely from behaviour:

  * Regularity   : how tightly inter-arrival times cluster around their median
                   (MAD-based jitter, share of intervals inside a tolerance band,
                   dominant-period detection that also handles alternating
                   destinations / round-robin C2 pairs).
  * Persistence  : number of connections and how long the channel stays alive.
  * Size profile : beacons usually send/receive near-constant payloads.
  * Rarity       : channels toward external hosts only (by default).

Usage:
    python3 beacon_detect.py conn.log
    python3 beacon_detect.py conn.log --top 15 --min-conns 8 --csv out.csv
    python3 beacon_detect.py conn.log --include-internal --json out.json
"""
import argparse
import csv
import ipaddress
import json
import math
import statistics as st
import sys
from collections import defaultdict
from datetime import datetime, timezone


# ----------------------------------------------------------------- parsing
def parse_zeek(path):
    """Yield dict rows from a Zeek conn.log (TSV with #fields header, or JSON lines)."""
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
                elif line.startswith("#unset_field"):
                    unset = line.split(sep if sep in line else None, 1)[-1].strip()
                elif line.startswith("#fields"):
                    fields = line.split(sep)[1:]
                continue
            if line.lstrip().startswith("{"):
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
                continue
            if fields is None:
                continue
            parts = line.split(sep)
            if len(parts) < len(fields):
                continue
            yield {k: (None if v == unset else v) for k, v in zip(fields, parts)}


def num(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_private or a.is_multicast or a.is_loopback or a.is_link_local or a.is_reserved


# ----------------------------------------------------------------- statistics
def median_abs_dev(xs, med):
    return st.median(abs(x - med) for x in xs)


def best_period(intervals, tol=0.25):
    """Return (period, fraction_of_intervals_matching) for the dominant period.
    Candidates: the median, and the median of the short half (catches bursts)."""
    med = st.median(intervals)
    cands = {med}
    srt = sorted(intervals)
    cands.add(st.median(srt[: max(1, len(srt) // 2)]))
    best = (med, 0.0)
    for c in cands:
        if c <= 0:
            continue
        frac = sum(1 for x in intervals if abs(x - c) <= tol * c) / len(intervals)
        if frac > best[1]:
            best = (c, frac)
    return best


def size_consistency(vals, band=0.12):
    """Share of values that fall in the single biggest size cluster (+-band).
    1.0 = every payload has (nearly) the same size; handles bimodal traffic
    (e.g. check-in vs tasking) better than a plain coefficient of variation."""
    vals = sorted(v for v in vals if v is not None)
    if len(vals) < 3:
        return 0.0
    best, j = 0, 0
    for i, v in enumerate(vals):
        while vals[j] < v * (1 - band) - 1:
            j += 1
        # window [vals[j], v] must stay inside +-band of its centre
        while j < i and (v - vals[j]) > 2 * band * max(v, 1):
            j += 1
        best = max(best, i - j + 1)
    return best / len(vals)


def coverage(times, cap_start, cap_end, buckets=24):
    """Fraction of equal time windows of the whole capture in which the channel
    appears. Beacons keep showing up; one-off transfers do not."""
    span = cap_end - cap_start
    if span <= 0:
        return 0.0
    hit = {min(buckets - 1, int((t - cap_start) / span * buckets)) for t in times}
    return len(hit) / buckets


def autocorr_peak(times, bin_s):
    """Strength of periodicity via autocorrelation of the binned event series
    (robust against missing beats). Returns value in [0,1]."""
    if len(times) < 6 or bin_s <= 0:
        return 0.0
    t0 = times[0]
    n = int((times[-1] - t0) / bin_s) + 1
    if n < 8 or n > 200_000:
        return 0.0
    series = [0.0] * n
    for t in times:
        series[int((t - t0) / bin_s)] += 1.0
    mean = sum(series) / n
    x = [v - mean for v in series]
    denom = sum(v * v for v in x)
    if denom == 0:
        return 0.0
    best = 0.0
    for lag in range(1, min(n // 2, 600)):
        ac = sum(x[i] * x[i + lag] for i in range(n - lag)) / denom
        best = max(best, ac)
    return max(0.0, min(1.0, best))


# ----------------------------------------------------------------- scoring
def analyse_channel(key, recs, args):
    recs.sort(key=lambda r: r["ts"])
    times = [r["ts"] for r in recs]
    # collapse near-simultaneous connections (parallel sockets of the same beat)
    dedup = [times[0]]
    for t in times[1:]:
        if t - dedup[-1] > args.dedup:
            dedup.append(t)
    times = dedup
    n = len(times)
    if n < args.min_conns:
        return None

    intervals = [b - a for a, b in zip(times, times[1:])]
    med = st.median(intervals)
    if med < args.min_interval:
        return None
    mad = median_abs_dev(intervals, med)
    jitter = (1.4826 * mad) / med if med else 1.0          # robust CV
    period, frac = best_period(intervals, args.tolerance)
    span = times[-1] - times[0]

    sc_reg = max(0.0, 1.0 - min(1.0, jitter))                # tight spacing
    sc_frac = frac                                           # share on-period
    sc_cnt = min(1.0, math.log(n, 2) / math.log(40, 2))      # saturates at ~40 conns
    sc_span = min(1.0, span / args.span_ref)                 # lives long enough
    sc_up = size_consistency([r["orig"] for r in recs])
    sc_dn = size_consistency([r["resp"] for r in recs])
    sc_size = 0.6 * sc_up + 0.4 * sc_dn
    sc_ac = autocorr_peak(times, max(period / 2.0, 0.5))
    sc_cov = coverage(times, args.cap_start, args.cap_end)

    # Regular-timer beacons (tight spacing) and sleep+jitter beacons (loose
    # spacing but persistent, same-size, always present) are both rewarded.
    score = 100 * (0.20 * sc_reg + 0.12 * sc_frac + 0.18 * sc_cnt +
                   0.05 * sc_span + 0.20 * sc_size + 0.05 * sc_ac +
                   0.20 * sc_cov)

    # penalise very bulky channels (downloads / streaming, not tasking traffic)
    avg_bytes = st.mean(r["orig"] + r["resp"] for r in recs)
    if avg_bytes > args.bulk_bytes:
        score *= 0.75

    return {
        "src": key[0], "dst": key[1], "dport": key[2], "proto": key[3],
        "conns": n, "first": times[0], "last": times[-1], "span_s": span,
        "median_interval_s": med, "period_s": period,
        "on_period_pct": 100 * frac, "jitter_pct": 100 * jitter,
        "size_consistency_pct": 100 * sc_size, "autocorr": sc_ac,
        "coverage_pct": 100 * sc_cov,
        "avg_bytes": avg_bytes, "score": score,
    }


def grade(score):
    return ("HIGH" if score >= 75 else "MEDIUM" if score >= 60 else "LOW")


def fmt_t(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%H:%M:%S")


# ----------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Generic Zeek conn.log beacon detector")
    ap.add_argument("logfile")
    ap.add_argument("--min-conns", type=int, default=8)
    ap.add_argument("--min-interval", type=float, default=1.0, help="ignore periods shorter than N sec")
    ap.add_argument("--tolerance", type=float, default=0.25, help="on-period band (fraction of period)")
    ap.add_argument("--dedup", type=float, default=0.5, help="merge conns closer than N sec")
    ap.add_argument("--span-ref", type=float, default=600.0, help="seconds of activity for full persistence score")
    ap.add_argument("--bulk-bytes", type=float, default=200_000)
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--include-internal", action="store_true", help="also analyse internal->internal flows")
    ap.add_argument("--keep-empty", action="store_true", help="keep 0-byte records (default: dropped)")
    ap.add_argument("--protos", default="tcp,udp")
    ap.add_argument("--csv")
    ap.add_argument("--json")
    args = ap.parse_args()

    protos = set(args.protos.split(","))
    chans = defaultdict(list)
    total = 0
    all_ts = []
    for row in parse_zeek(args.logfile):
        total += 1
        ts = num(row.get("ts"))
        if ts:
            all_ts.append(ts)
        src, dst = row.get("id.orig_h"), row.get("id.resp_h")
        if not src or not dst or row.get("proto") not in protos:
            continue
        # empty teardown/ack-only records (0 bytes both ways) are artefacts
        # that distort inter-arrival times
        if not args.keep_empty and num(row.get("orig_bytes")) == 0 and num(row.get("resp_bytes")) == 0:
            continue
        if not args.include_internal and is_private(dst):
            continue
        chans[(src, dst, row.get("id.resp_p"), row.get("proto"))].append({
            "ts": num(row.get("ts")),
            "orig": num(row.get("orig_bytes")),
            "resp": num(row.get("resp_bytes")),
        })

    args.cap_start, args.cap_end = (min(all_ts), max(all_ts)) if all_ts else (0, 0)
    results = [r for k, v in chans.items() if (r := analyse_channel(k, v, args))]
    results.sort(key=lambda r: r["score"], reverse=True)

    print(f"[*] {total} conn records, {len(chans)} candidate channels, {len(results)} scored\n")
    hdr = f"{'#':>2} {'SCORE':>5} {'LVL':<6} {'SRC':<12} {'DST':<17}{'PORT':>5} {'CONNS':>5} " \
          f"{'PERIOD':>8} {'ON-PER%':>7} {'JITTER%':>7} {'SIZE%':>6} {'COVER%':>6} {'ACTIVE':<17}"
    print(hdr)
    print("-" * len(hdr))
    for i, r in enumerate(results[: args.top], 1):
        print(f"{i:>2} {r['score']:>5.1f} {grade(r['score']):<6} {r['src']:<12} {r['dst']:<17}"
              f"{r['dport']:>5} {r['conns']:>5} {r['period_s']:>7.1f}s {r['on_period_pct']:>7.0f} "
              f"{r['jitter_pct']:>7.1f} {r['size_consistency_pct']:>6.0f} {r['coverage_pct']:>6.0f} "
              f"{fmt_t(r['first'])}-{fmt_t(r['last'])}")

    if args.csv and results:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
            w.writeheader()
            w.writerows(results)
        print(f"\n[+] CSV written: {args.csv}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] JSON written: {args.json}")


if __name__ == "__main__":
    sys.exit(main())
