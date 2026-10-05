# Alert Review

Triage of every alert-worthy behavior found in the Zeek logs (`conn`, `dns`, `http`, `dhcp`, `ntp`, `packet_filter`) and the readable evidence PCAPs (`evidence-beacon`, `evidence-dns`, `evidence-port4444`). Times are UTC. Source data: `alert-review.csv`.

> **Evidence gap:** `evidence-exfil.pcapng` was unavailable, so AR-010 and AR-011 rest on Zeek metadata only.

## Summary

**22 alerts reviewed.**

### By disposition

| Disposition | Alerts |
|---|---|
| True Positive - Lab Generated | 10 |
| Benign | 6 |
| Informational | 4 |
| Data Quality | 2 |

### By severity

| Severity | Alerts |
|---|---|
| Medium | 6 |
| Low | 6 |
| Info | 10 |

### By finding

| Finding | Alerts |
|---|---|
| F-001 | AR-001, AR-002, AR-003 |
| F-002 | AR-004, AR-005, AR-006, AR-007, AR-008, AR-009, AR-015 |
| F-003 | AR-010, AR-011 |
| F-004 | AR-012, AR-013, AR-014 |
| No finding (baseline, infrastructure, sensor) | AR-016, AR-017, AR-018, AR-019, AR-020, AR-021, AR-022 |

## Alert Queue

| ID | First seen | Alert | Severity | Source | Destination | Events | Disposition |
|---|---|---|---|---|---|---|---|
| AR-001 | 2026-10-03 20:45:49 | Periodic HTTP beaconing | Medium | 192.168.40.1 (30 ports) | 192.168.40.129:8000 | 30 | True Positive - Lab Generated |
| AR-002 | 2026-10-03 20:45:49 | Scripted HTTP user agent | Low | 192.168.40.1 (various ports) | 192.168.40.129:8000 | 30 | True Positive - Lab Generated |
| AR-003 | 2026-10-03 20:45:49 | HTTP 404 responses to beacon URI | Info | 192.168.40.129:8000 | 192.168.40.1 (various ports) | 30 | Informational |
| AR-004 | 2026-10-05 14:03:41 | DNS queries for suspicious domain | Medium | 192.168.40.1 (various ports) | 192.168.40.129:53 | 33 | True Positive - Lab Generated |
| AR-005 | 2026-10-05 14:05:08 | High-entropy long DNS labels | Medium | 192.168.40.1 (various ports) | 192.168.40.129:53 | 12 | True Positive - Lab Generated |
| AR-006 | 2026-10-05 14:03:43 | DNS query for random-subdomain label | Low | 192.168.40.1 (ports 57116–57119) | 192.168.40.129:53 | 4 | True Positive - Lab Generated |
| AR-007 | 2026-10-05 14:03:41 | DNS sent to non-resolver host | Medium | 192.168.40.1 (various ports) | 192.168.40.129:53 | 33 | True Positive - Lab Generated |
| AR-008 | 2026-10-05 14:03:41 | ICMP port unreachable for DNS | Info | 192.168.40.129 (ICMP type 3) | 192.168.40.1 | 33 | Informational |
| AR-009 | 2026-10-03 20:43:30 | Random hex-label DNS queries (example.com) | Low | 192.168.40.129 (various ports) | 192.168.40.2:53 | 6 | True Positive - Lab Generated |
| AR-010 | 2026-10-03 20:52:59 | Large TCP transfer to internal host | Medium | 192.168.40.1:65137 | 192.168.40.129:5555 | 1 | True Positive - Lab Generated |
| AR-011 | 2026-10-03 20:52:59 | Zeek byte count vs packet count mismatch | Low | 192.168.40.1:65137 | 192.168.40.129:5555 | 1 | Data Quality |
| AR-012 | 2026-10-03 20:38:41 | TCP session on port 4444 | Medium | 192.168.40.1:48924 | 192.168.40.129:4444 | 1 | True Positive - Lab Generated |
| AR-013 | 2026-10-03 20:39:24 | LAB_TEST payload on port 4444 | Low | 192.168.40.1:48924 | 192.168.40.129:4444 | 3 | True Positive - Lab Generated |
| AR-014 | 2026-10-03 20:38:41 | Single session split into two Zeek records | Info | 192.168.40.1:48924 | 192.168.40.129:4444 | 2 | Data Quality |
| AR-015 | 2026-10-05 14:02:57 | ICMP echo before DNS activity | Low | 192.168.40.1 (ICMP echo) | 192.168.40.129 | 1 | Informational |
| AR-016 | 2026-10-03 20:38:14 | NTP time synchronization | Info | 192.168.40.129 (various ports) | 196.44.136.165; 196.10.55.57; 196.10.54.57:123 | 57 | Benign |
| AR-017 | 2026-10-03 20:38:11 | DHCP lease activity | Info | 192.168.40.129; 192.168.40.1:67/68 | 192.168.40.254:67 | 5 | Benign |
| AR-018 | 2026-10-03 20:42:17 | LLMNR / mDNS multicast name queries | Info | 192.168.40.1; fe80::5742:1fbe:ce5a:ea5a:5353/5355 | 224.0.0.251/252; ff02::1:3:5353/5355 | 7 | Benign |
| AR-019 | 2026-10-03 20:42:17 | IGMP / MLD multicast membership | Info | 192.168.40.1; fe80::5742:1fbe:ce5a:ea5a | 224.0.0.22; ff02::16:0 | 4 | Benign |
| AR-020 | 2026-10-03 20:44:42 | Mozilla DNS lookups | Info | 192.168.40.129 (various ports) | 192.168.40.2:53 | 4 | Benign |
| AR-021 | 2026-10-03 20:39:54 | HTTPS to Mozilla/Fastly addresses | Info | 192.168.40.129 (various ports) | 199.232.81.91; 34.107.243.93:443 | 15 | Benign |
| AR-022 | 2026-10-05 14:08:10 | Zeek sensor started | Info | — | — | 1 | Informational |

## Alert Details

### AR-001 — Periodic HTTP beaconing

| Field | Value |
|---|---|
| Category | Command and Control |
| Severity | Medium |
| Window | 2026-10-03 20:45:49 → 2026-10-03 21:00:20 |
| Source | 192.168.40.1 (30 ports) |
| Destination | 192.168.40.129:8000 |
| Protocol | tcp/http |
| Events | 30 |
| Finding | F-001 |
| Evidence | http.log; conn.log; evidence-beacon.pcapng |
| Disposition | True Positive - Lab Generated (High confidence) |

**Detail:** 30 identical GET /beacon requests; interval mean 30.03s, stdev 0.11s, min 29.77s, max 30.42s

**Analyst notes:** Near-perfect cadence with constant URI; new TCP connection per request

**Recommended action:** Document as intentional; in production, identify the sending process and baseline against normal traffic

### AR-002 — Scripted HTTP user agent

| Field | Value |
|---|---|
| Category | Anomalous Client |
| Severity | Low |
| Window | 2026-10-03 20:45:49 → 2026-10-03 21:00:20 |
| Source | 192.168.40.1 (various ports) |
| Destination | 192.168.40.129:8000 |
| Protocol | tcp/http |
| Events | 30 |
| Finding | F-001 |
| Evidence | http.log; evidence-beacon.pcapng |
| Disposition | True Positive - Lab Generated (Medium confidence) |

**Detail:** User-Agent python-requests/2.34.2; no Referer or cookies; Accept-Encoding gzip, deflate, zstd

**Analyst notes:** Scripted client, not a browser; supports AR-001

**Recommended action:** Alert on python-requests UA in beacon-like patterns

### AR-003 — HTTP 404 responses to beacon URI

| Field | Value |
|---|---|
| Category | Server Response |
| Severity | Info |
| Window | 2026-10-03 20:45:49 → 2026-10-03 21:00:20 |
| Source | 192.168.40.129:8000 |
| Destination | 192.168.40.1 (various ports) |
| Protocol | tcp/http |
| Events | 30 |
| Finding | F-001 |
| Evidence | evidence-beacon.pcapng |
| Disposition | Informational (High confidence) |

**Detail:** Identical 335-byte Python http.server style 404 page for every request; no tasking or data returned

**Analyst notes:** Status line and headers absent from evidence file, so Zeek status_code is empty

**Recommended action:** None; note that no C2 tasking was observed

### AR-004 — DNS queries for suspicious domain

| Field | Value |
|---|---|
| Category | Command and Control |
| Severity | Medium |
| Window | 2026-10-05 14:03:41 → 2026-10-05 14:06:03 |
| Source | 192.168.40.1 (various ports) |
| Destination | 192.168.40.129:53 |
| Protocol | udp/dns |
| Events | 33 |
| Finding | F-002 |
| Evidence | dns.log; conn.log; evidence-dns.pcapng |
| Disposition | True Positive - Lab Generated (High confidence) |

**Detail:** 33 queries for malicious-c2.xyz (A/AAAA plus PTR of 129.40.168.192.in-addr.arpa) across 7 runs

**Analyst notes:** nslookup-style pattern, about 2s between queries, about 10.5s between runs

**Recommended action:** Block or sinkhole malicious-c2.xyz in production; alert on repeat lookups

### AR-005 — High-entropy long DNS labels

| Field | Value |
|---|---|
| Category | Possible DNS Tunneling |
| Severity | Medium |
| Window | 2026-10-05 14:05:08 → 2026-10-05 14:06:03 |
| Source | 192.168.40.1 (various ports) |
| Destination | 192.168.40.129:53 |
| Protocol | udp/dns |
| Events | 12 |
| Finding | F-002 |
| Evidence | dns.log; evidence-dns.pcapng |
| Disposition | True Positive - Lab Generated (Medium confidence) |

**Detail:** 6 random 20-character labels (entropy 4.32 bits/char), each queried A/AAAA, e.g. lxpht4i9n7vqug5w3mfr.malicious-c2.xyz

**Analyst notes:** All 20 characters distinct in each label, suggesting scripted generation, not encoded data; no payload shown

**Recommended action:** Add entropy and length detection for DNS labels

### AR-006 — DNS query for random-subdomain label

| Field | Value |
|---|---|
| Category | Possible DNS Tunneling |
| Severity | Low |
| Window | 2026-10-05 14:03:43 → 2026-10-05 14:03:49 |
| Source | 192.168.40.1 (ports 57116–57119) |
| Destination | 192.168.40.129:53 |
| Protocol | udp/dns |
| Events | 4 |
| Finding | F-002 |
| Evidence | dns.log; evidence-dns.pcapng |
| Disposition | True Positive - Lab Generated (High confidence) |

**Detail:** random-subdomain.malicious-c2.xyz queried A/AAAA twice each; first run of the series

**Analyst notes:** 16 chars, entropy 3.38; human-readable placeholder label

**Recommended action:** Include in domain blocklist with AR-004

### AR-007 — DNS sent to non-resolver host

| Field | Value |
|---|---|
| Category | Anomalous DNS Path |
| Severity | Medium |
| Window | 2026-10-05 14:03:41 → 2026-10-05 14:06:03 |
| Source | 192.168.40.1 (various ports) |
| Destination | 192.168.40.129:53 |
| Protocol | udp/dns |
| Events | 33 |
| Finding | F-002 |
| Evidence | conn.log; evidence-dns.pcapng |
| Disposition | True Positive - Lab Generated (Medium confidence) |

**Detail:** Queries went to 192.168.40.129 instead of lab resolver 192.168.40.2; recursion desired set

**Analyst notes:** Victim used the Kali host as its DNS server for this domain

**Recommended action:** Alert when hosts query internal non-DNS servers on UDP/53

### AR-008 — ICMP port unreachable for DNS

| Field | Value |
|---|---|
| Category | Unanswered Service |
| Severity | Info |
| Window | 2026-10-05 14:03:41 → 2026-10-05 14:06:03 |
| Source | 192.168.40.129 (ICMP type 3) |
| Destination | 192.168.40.1 |
| Protocol | icmp |
| Events | 33 |
| Finding | F-002 |
| Evidence | evidence-dns.pcapng; conn.log |
| Disposition | Informational (High confidence) |

**Detail:** 33 ICMP type 3 code 3 replies, one per query; nothing listening on UDP/53 of 192.168.40.129

**Analyst notes:** Explains why no DNS answers exist and why no data exchange is shown

**Recommended action:** 

### AR-009 — Random hex-label DNS queries (example.com)

| Field | Value |
|---|---|
| Category | Possible DNS Tunneling |
| Severity | Low |
| Window | 2026-10-03 20:43:30 → 2026-10-03 20:43:35 |
| Source | 192.168.40.129 (various ports) |
| Destination | 192.168.40.2:53 |
| Protocol | udp/dns |
| Events | 6 |
| Finding | F-002 |
| Evidence | dns.log; evidence-dns.pcapng |
| Disposition | True Positive - Lab Generated (Medium confidence) |

**Detail:** 8f72a91c32, 92ad81c72f, a7812bc981 under example.com; A and AAAA, 1s apart; empty NOERROR responses

**Analyst notes:** Zeek dns.log recorded these with no query name; the capture shows the names

**Recommended action:** Investigate normal-resolver queries for random names in production

### AR-010 — Large TCP transfer to internal host

| Field | Value |
|---|---|
| Category | Possible Exfiltration |
| Severity | Medium |
| Window | 2026-10-03 20:52:59 → 2026-10-03 20:53:00 |
| Source | 192.168.40.1:65137 |
| Destination | 192.168.40.129:5555 |
| Protocol | tcp |
| Events | 1 |
| Finding | F-003 |
| Evidence | conn.log |
| Disposition | True Positive - Lab Generated (Medium confidence) |

**Detail:** 52,428,800 bytes (50 MiB) client to server in 0.99s; 0 bytes returned

**Analyst notes:** Exact 50 MiB suggests a generated test file; evidence-exfil.pcapng unavailable, so packet-level check pending

**Recommended action:** Re-upload exfil pcap and confirm transferred content and completion

### AR-011 — Zeek byte count vs packet count mismatch

| Field | Value |
|---|---|
| Category | Data Quality |
| Severity | Low |
| Window | 2026-10-03 20:52:59 → 2026-10-03 20:53:00 |
| Source | 192.168.40.1:65137 |
| Destination | 192.168.40.129:5555 |
| Protocol | tcp |
| Events | 1 |
| Finding | F-003 |
| Evidence | conn.log |
| Disposition | Data Quality (High confidence) |

**Detail:** 56 packets and 75,900 IP bytes recorded against 52,428,800 payload bytes

**Analyst notes:** Zeek counts bytes from sequence numbers; capture appears to hold only part of the flow

**Recommended action:** Verify capture completeness and snaplen

### AR-012 — TCP session on port 4444

| Field | Value |
|---|---|
| Category | Non-Standard Port |
| Severity | Medium |
| Window | 2026-10-03 20:38:41 → 2026-10-03 20:42:05 |
| Source | 192.168.40.1:48924 |
| Destination | 192.168.40.129:4444 |
| Protocol | tcp |
| Events | 1 |
| Finding | F-004 |
| Evidence | conn.log; evidence-port4444.pcapng |
| Disposition | True Positive - Lab Generated (High confidence) |

**Detail:** Complete handshake; 204.9s session with no FIN or RST; server sent no data

**Analyst notes:** Port 4444 is a common default for offensive tools but payload here is test text

**Recommended action:** Confirm service and process on the listener in production

### AR-013 — LAB_TEST payload on port 4444

| Field | Value |
|---|---|
| Category | Anomalous Payload |
| Severity | Low |
| Window | 2026-10-03 20:39:24 → 2026-10-03 20:42:05 |
| Source | 192.168.40.1:48924 |
| Destination | 192.168.40.129:4444 |
| Protocol | tcp |
| Events | 3 |
| Finding | F-004 |
| Evidence | evidence-port4444.pcapng |
| Disposition | True Positive - Lab Generated (High confidence) |

**Detail:** Three 9-byte messages "LAB_TEST\n" at +43.3s, +76.8s and +204.9s (27 bytes total); irregular timing

**Analyst notes:** Plain labelled text, no shell prompt, commands or binary content

**Recommended action:** None; supports the lab-generated conclusion

### AR-014 — Single session split into two Zeek records

| Field | Value |
|---|---|
| Category | Data Quality |
| Severity | Info |
| Window | 2026-10-03 20:38:41 → 2026-10-03 20:42:05 |
| Source | 192.168.40.1:48924 |
| Destination | 192.168.40.129:4444 |
| Protocol | tcp |
| Events | 2 |
| Finding | F-004 |
| Evidence | conn.log; evidence-port4444.pcapng |
| Disposition | Data Quality (High confidence) |

**Detail:** conn.log shows one S0 record and one OTH record of 161.6s; the capture shows one 204.9s session

**Analyst notes:** Zeek tracking artifact; count it as one connection

**Recommended action:** Use pcap view for session length and byte counts

### AR-015 — ICMP echo before DNS activity

| Field | Value |
|---|---|
| Category | Reconnaissance |
| Severity | Low |
| Window | 2026-10-05 14:02:57 → 2026-10-05 14:02:57 |
| Source | 192.168.40.1 (ICMP echo) |
| Destination | 192.168.40.129 |
| Protocol | icmp |
| Events | 1 |
| Finding | F-002 |
| Evidence | conn.log |
| Disposition | Informational (Low confidence) |

**Detail:** Echo request and reply, 128 bytes each way, about 1 minute before the first malicious-c2.xyz query

**Analyst notes:** Likely reachability check by the lab operator

**Recommended action:** 

### AR-016 — NTP time synchronization

| Field | Value |
|---|---|
| Category | Normal Infrastructure |
| Severity | Info |
| Window | 2026-10-03 20:38:14 → 2026-10-05 14:06:00 |
| Source | 192.168.40.129 (various ports) |
| Destination | 196.44.136.165; 196.10.55.57; 196.10.54.57:123 |
| Protocol | udp/ntp |
| Events | 57 |
| Finding | — |
| Evidence | ntp.log; conn.log |
| Disposition | Benign (High confidence) |

**Detail:** Regular polling roughly every 30s (13 + 31 + 13 exchanges across three servers)

**Analyst notes:** Reference-time fields look unusual but traffic is routine

**Recommended action:** 

### AR-017 — DHCP lease activity

| Field | Value |
|---|---|
| Category | Normal Infrastructure |
| Severity | Info |
| Window | 2026-10-03 20:38:11 → 2026-10-05 14:05:55 |
| Source | 192.168.40.129; 192.168.40.1:67/68 |
| Destination | 192.168.40.254:67 |
| Protocol | udp/dhcp |
| Events | 5 |
| Finding | — |
| Evidence | dhcp.log; conn.log |
| Disposition | Benign (High confidence) |

**Detail:** Lease renewals, 1800s lease time; EZZAT-PC and the Kali host ACKed

**Analyst notes:** Gives hostname EZZAT-PC and MACs for both hosts

**Recommended action:** 

### AR-018 — LLMNR / mDNS multicast name queries

| Field | Value |
|---|---|
| Category | Normal Infrastructure |
| Severity | Info |
| Window | 2026-10-03 20:42:17 → 2026-10-03 20:57:26 |
| Source | 192.168.40.1; fe80::5742:1fbe:ce5a:ea5a:5353/5355 |
| Destination | 224.0.0.251/252; ff02::1:3:5353/5355 |
| Protocol | udp/dns |
| Events | 7 |
| Finding | — |
| Evidence | dns.log; conn.log |
| Disposition | Benign (High confidence) |

**Detail:** Windows host queries for ezzat-pc and _sleep-proxy._udp.local

**Analyst notes:** Standard Windows name resolution; LLMNR can be abused in real networks

**Recommended action:** Disable LLMNR where not needed

### AR-019 — IGMP / MLD multicast membership

| Field | Value |
|---|---|
| Category | Normal Infrastructure |
| Severity | Info |
| Window | 2026-10-03 20:42:17 → 2026-10-03 20:57:26 |
| Source | 192.168.40.1; fe80::5742:1fbe:ce5a:ea5a |
| Destination | 224.0.0.22; ff02::16:0 |
| Protocol | igmp/icmpv6 |
| Events | 4 |
| Finding | — |
| Evidence | conn.log |
| Disposition | Benign (High confidence) |

**Detail:** Group membership reports from the victim host

**Analyst notes:** Normal host behavior

**Recommended action:** 

### AR-020 — Mozilla DNS lookups

| Field | Value |
|---|---|
| Category | Normal Browser Traffic |
| Severity | Info |
| Window | 2026-10-03 20:44:42 → 2026-10-03 20:59:47 |
| Source | 192.168.40.129 (various ports) |
| Destination | 192.168.40.2:53 |
| Protocol | udp/dns |
| Events | 4 |
| Finding | — |
| Evidence | dns.log; evidence-dns.pcapng |
| Disposition | Benign (High confidence) |

**Detail:** ads.mozilla.org and push.services.mozilla.com answered (199.232.81.91, 34.107.243.93)

**Analyst notes:** Baseline resolver traffic

**Recommended action:** 

### AR-021 — HTTPS to Mozilla/Fastly addresses

| Field | Value |
|---|---|
| Category | Normal Browser Traffic |
| Severity | Info |
| Window | 2026-10-03 20:39:54 → 2026-10-03 20:59:47 |
| Source | 192.168.40.129 (various ports) |
| Destination | 199.232.81.91; 34.107.243.93:443 |
| Protocol | tcp |
| Events | 15 |
| Finding | — |
| Evidence | conn.log |
| Disposition | Benign (Medium confidence) |

**Detail:** 15 flows (6 + 9), mid-stream and RST states; addresses match the Mozilla DNS answers

**Analyst notes:** Firefox background traffic on the Kali host; partial captures explain odd states

**Recommended action:** 

### AR-022 — Zeek sensor started

| Field | Value |
|---|---|
| Category | Sensor Health |
| Severity | Info |
| Window | 2026-10-05 14:08:10 → 2026-10-05 14:08:10 |
| Source | — |
| Destination | — |
| Protocol | — |
| Events | 1 |
| Finding | — |
| Evidence | packet_filter.log |
| Disposition | Informational (High confidence) |

**Detail:** Packet filter "ip or not ip" initialised successfully

**Analyst notes:** Confirms capture was unfiltered at start

**Recommended action:** 
