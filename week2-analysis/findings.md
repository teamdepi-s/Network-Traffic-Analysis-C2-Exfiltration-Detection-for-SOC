# Week 2 — Network Anomaly Analysis

## Lab Scope

| Item | Detail |
|---|---|
| Environment | Controlled network-analysis lab |
| Hosts | Kali Linux analysis host and a lab victim host |
| Capture type | Controlled lab traffic |
| Analysis tools | Wireshark, Zeek, Suricata, TShark |
| Packet-level validation (this write-up) | Evidence PCAPs parsed programmatically (Scapy) and cross-checked against Zeek logs; filters below reproduce each view in Wireshark |
| Analysis window (UTC) | 2026-10-03 20:38 – 21:00 and 2026-10-05 14:02 – 14:06 |

### Host roles

Roles follow the lab description and are supported by the packet evidence (TTL and MAC vendor).

| Role | IP address | Identifiers | Evidence for role |
|---|---|---|---|
| Lab victim | `192.168.40.1` | Hostname `EZZAT-PC` | TTL 128 (Windows-like); initiates every anomalous flow |
| Kali analysis host | `192.168.40.129` |  (VMware) | TTL 64 (Linux-like); HTTP server on 8000, listener on 4444 and 5555 |
| Lab DNS resolver | `192.168.40.2` | — | Answers normal DNS queries |
| Lab DHCP server | `192.168.40.254` | — | Lease renewals only |

## Captured PCAP

| File | Role | Packets | Time window (UTC) | Status |
|---|---|---|---|---|
| `pcaps/attack.pcapng` | Full lab capture | n/a | n/a | Referenced; not part of this analysis upload |
| `pcaps/evidence-beacon.pcapng` | F-001 evidence | 60 | 2026-10-03 20:45:49 – 21:00:20 | Analyzed |
| `pcaps/evidence-dns.pcapng` | F-002 evidence | 86 | 2026-10-03 20:43:30 – 2026-10-05 14:06:03 | Analyzed |
| `pcaps/evidence-exfil.pcapng` | F-003 evidence | n/a | n/a | Not available (see note under F-003) |
| `pcaps/evidence-port4444.pcapng` | F-004 evidence | 9 | 2026-10-03 20:38:41 – 20:42:05 | Analyzed |

## Findings Summary

| ID | Finding | Severity | Key observation | Evidence PCAP | Validation |
|---|---|---|---|---|---|
| F-001 | Periodic HTTP Beaconing | Medium | 30 identical `GET /beacon` requests, mean interval 30.03 s | `evidence-beacon.pcapng` | Intentionally generated |
| F-002 | Suspicious DNS Query Pattern | Medium | 33 queries for 7 random 20-character subdomains of `malicious-c2.xyz`; all met ICMP port unreachable | `evidence-dns.pcapng` | Intentionally generated |
| F-003 | Large Internal File Transfer | Medium | One TCP flow of 52,428,800 bytes (50 MiB) to port 5555 | `evidence-exfil.pcapng` | Intentionally generated |
| F-004 | Unusual TCP Port 4444 | Medium | One completed session, three `LAB_TEST` messages | `evidence-port4444.pcapng` | Intentionally generated |

---

## Finding F-001 — Periodic HTTP Beaconing

**Severity:** Medium

**Description:**
The victim generated repeated HTTP GET requests to the lab HTTP server at approximately regular 30-second intervals.

**Evidence:**

* PCAP: `pcaps/attack.pcapng`
* Evidence PCAP: `pcaps/evidence-beacon.pcapng`
* Screenshot: `screenshots/beacon.png`
* Wireshark filter: `http.request.uri contains "beacon"`

**Observed Behavior:**
The HTTP requests occurred repeatedly with approximately consistent timing.

| Attribute | Value |
|---|---|
| Client → server | `192.168.40.1` → `192.168.40.129:8000/tcp` |
| Requests observed | 30 (first 2026-10-03 20:45:49.643 UTC, last 21:00:20 UTC) |
| Request | `GET /beacon HTTP/1.1`, identical in all 30 requests (162 bytes of payload) |
| User-Agent | `python-requests/2.34.2` |
| Other headers | `Accept: */*`, `Accept-Encoding: gzip, deflate, zstd`, `Connection: keep-alive`; no Referer, no cookies |
| Interval (29 gaps) | min 29.77 s, max 30.42 s, mean 30.03 s, median 30.03 s, standard deviation 0.11 s |
| Connection pattern | A new TCP connection (new source port) for every request: 30 requests, 30 distinct source ports |
| Server response | Identical 335-byte HTML "Error 404 – File not found" page for every request |

The 404 body has the format of Python's built-in `http.server`. The status line and headers are not present in the evidence file, which only holds the data segments (this is also why Zeek's `http.log` has empty status fields).

**Why Suspicious:**
Periodic automated connections can be consistent with beaconing behavior. In a real environment, the destination reputation, process responsible for the traffic, domain age, HTTP headers, and historical baseline would need to be investigated before declaring the activity malicious.

Points that fit beaconing here: fixed 30-second cadence with under 0.4% jitter, a scripted client user agent, a constant URI, and no human-driven variation. A counterpoint is that the server answers 404, so no tasking or data is returned.

**Validation:**
The behavior was intentionally generated as part of the controlled lab exercise.

---

## Finding F-002 — Suspicious DNS Query Pattern

**Severity:** Medium

**Description:**
Repeated DNS queries containing unusually long/random-looking subdomains were observed.

**Evidence:**

* PCAP: `pcaps/attack.pcapng`
* Evidence PCAP: `pcaps/evidence-dns.pcapng`
* Screenshot: `screenshots/dns.png`
* Wireshark filter: `dns`

**Observed Behavior:**

| Attribute | Value |
|---|---|
| Queries for the suspicious domain | 33 UDP/53 queries, `192.168.40.1` → `192.168.40.129` (not the lab resolver `.2`) |
| Time window | 2026-10-05 14:03:41 – 14:06:03 UTC |
| Parent domain | `malicious-c2.xyz` |
| Distinct names | 7: `random-subdomain` plus six 20-character random labels |
| Query types | A and AAAA, alternating, plus a PTR lookup of `129.40.168.192.in-addr.arpa` before each name |
| Spacing | About 2 s between queries; about 10.5 s between runs |
| Responses | None. All 33 queries received an ICMP type 3 / code 3 (port unreachable) from `192.168.40.129` |

Random 20-character labels observed:

| Label (under `.malicious-c2.xyz`) | Length | Shannon entropy (bits/char) |
|---|---|---|
| `lxpht4i9n7vqug5w3mfr` | 20 | 4.32 |
| `t7d2m1i6ycja8hbeg54z` | 20 | 4.32 |
| `f83s5xveji7tn1q2ugbr` | 20 | 4.32 |
| `l7fthbajv4q9p32mcoys` | 20 | 4.32 |
| `m9yjsbv2rk0a734qtngz` | 20 | 4.32 |
| `capf0hr7x65bqn981duw` | 20 | 4.32 |
| `random-subdomain` (first run) | 16 | 3.38 |

The query pattern (PTR for the server's address, then A/AAAA retried every 2 s) matches an `nslookup`-style client run seven times against `192.168.40.129` as its DNS server.

Secondary observation: on 2026-10-03 at 20:43:30–35 UTC, `192.168.40.129` sent six queries (A and AAAA, one second apart) for three 10-character hex names under `example.com` (`8f72a91c32`, `92ad81c72f`, `a7812bc981`) to the lab resolver, which answered with empty NOERROR responses. Zeek's `dns.log` recorded these rows with no query name; the capture shows the names. The remaining resolver traffic (`ads.mozilla.org`, `push.services.mozilla.com`) was answered normally and serves as a baseline.

**Why Suspicious:**
Long and high-entropy DNS labels, especially when repeated at high frequency, can be associated with DNS tunneling or encoded data transfer. However, these characteristics alone do not prove tunneling.

Here every 20-character label uses 20 different characters (entropy exactly log₂ 20 = 4.32), which suggests the names were generated by a script rather than carrying encoded data. No query contained a payload pattern, and nothing answered, so no data exchange can be shown.

**Validation:**
The traffic was intentionally generated to simulate suspicious DNS characteristics in the lab.

---

## Finding F-003 — Large Internal File Transfer

**Severity:** Medium

**Description:**
A large volume of TCP data was transferred from the lab victim to the lab analysis host.

**Evidence:**

* PCAP: `pcaps/attack.pcapng`
* Evidence PCAP: `pcaps/evidence-exfil.pcapng`
* Wireshark TCP conversation analysis

**Observed Behavior:**

| Attribute | Value (from Zeek `conn.log`) |
|---|---|
| Flow | `192.168.40.1:65137` → `192.168.40.129:5555/tcp` |
| Time | 2026-10-03 about 20:52:59 UTC |
| Duration | 0.99 s |
| Client-to-server bytes | 52,428,800 (exactly 50 MiB) |
| Server-to-client bytes | 0 |
| Packets / IP bytes recorded | 56 packets / 75,900 bytes |

> **Evidence gap:** `evidence-exfil.pcapng` was not available for this analysis (the uploaded copy was 0 bytes), so this finding rests on Zeek metadata only. Zeek derives byte totals from TCP sequence numbers, and 56 packets cannot carry 50 MiB, so the capture appears to hold only part of the flow. Check the packet-level view once the file is re-uploaded.

**Why Suspicious:**
Unexpected large outbound transfers can be consistent with data exfiltration. In a real investigation, the destination, transferred file, user/process context, and business justification would need to be validated.

The exact 50 MiB size is consistent with a generated test file.

**Validation:**
The transfer was intentionally generated using a test file inside the controlled lab.

---

## Finding F-004 — Unusual TCP Port 4444

**Severity:** Medium

**Description:**
A TCP connection was established using destination port 4444.

**Evidence:**

* PCAP: `pcaps/attack.pcapng`
* Evidence PCAP: `pcaps/evidence-port4444.pcapng`
* Wireshark filter: `tcp.port == 4444`

**Observed Behavior:**

| Attribute | Value |
|---|---|
| Connection | `192.168.40.1:48924` → `192.168.40.129:4444/tcp` |
| Handshake | Complete three-way handshake at 2026-10-03 20:38:41 UTC |
| Session length | 204.9 s, no FIN or RST seen |
| Client data | Three 9-byte messages, each the ASCII text `LAB_TEST\n` (27 bytes total) |
| Message times | +43.3 s, +76.8 s, +204.9 s after connect (irregular, not periodic) |
| Server data | None; the server only acknowledged each message |

| Offset (s) | Direction | Flags | Payload |
|---|---|---|---|
| 0.0 | Client → server | SYN | — |
| 0.0 | Server → client | SYN, ACK | — |
| 0.0 | Client → server | ACK | — |
| 43.3 | Client → server | PSH, ACK | `LAB_TEST\n` |
| 76.8 | Client → server | PSH, ACK | `LAB_TEST\n` |
| 204.9 | Client → server | PSH, ACK | `LAB_TEST\n` |

Zeek recorded this single session as two `conn.log` entries (one `S0`, one `OTH` of 161.6 s). The packet capture shows one continuous connection, so the split is a Zeek tracking artifact.

**Why Suspicious:**
An unexpected listening service or connection on a non-standard port can warrant investigation. The port number alone is not sufficient to determine maliciousness.

Port 4444 is the default for several offensive tools, which is why it draws attention. The payload here is plain, labelled test text, with no shell prompt, commands or binary content.

**Validation:**
The connection was intentionally generated as part of the controlled lab exercise.

---

## Timeline

| Time (UTC) | Finding | Event |
|---|---|---|
| 2026-10-03 20:38:41 | F-004 | TCP handshake to `192.168.40.129:4444` |
| 2026-10-03 20:39:24 | F-004 | First `LAB_TEST` message (+43 s) |
| 2026-10-03 20:43:30 | F-002 | Hex-label queries under `example.com` sent to lab resolver |
| 2026-10-03 20:45:49 | F-001 | First `GET /beacon` |
| 2026-10-03 20:52:59 | F-003 | 50 MiB transfer to port 5555 |
| 2026-10-03 21:00:20 | F-001 | 30th beacon and response |
| 2026-10-05 14:03:41 | F-002 | First `malicious-c2.xyz` run begins |
| 2026-10-05 14:06:03 | F-002 | Last captured query |

## Indicators Observed

| Type | Value | Related finding |
|---|---|---|
| Domain | `malicious-c2.xyz` and its 7 subdomains | F-002 |
| URL | `http://192.168.40.129:8000/beacon` | F-001 |
| User-Agent | `python-requests/2.34.2` | F-001 |
| Port | `192.168.40.129:4444/tcp` | F-004 |
| Port | `192.168.40.129:5555/tcp` | F-003 |
| Payload string | `LAB_TEST` | F-004 |

The full list is in `iocs.csv`.

## Analyst Conclusion

The PCAP contained several intentionally generated anomalous behaviors:

1. Periodic HTTP beacon-like traffic.
2. Suspicious-looking DNS query patterns.
3. Large-volume TCP file transfer.
4. A TCP connection using port 4444.

The observations were validated against the controlled lab activity and analyzed using packet-level and network-metadata-based evidence.

Details that support the lab-generated conclusion: the beacon cadence is nearly perfect and always receives a 404, the DNS labels are scripted permutations with no answers, the 4444 payload is the literal string `LAB_TEST`, and the transfer is exactly 50 MiB.

## Limitations

* `evidence-exfil.pcapng` was unavailable, so F-003 is supported by Zeek metadata only and the byte count could not be confirmed against packets.
* `pcaps/attack.pcapng` and the screenshots (`screenshots/beacon.png`, `screenshots/dns.png`) were not part of this analysis and are cited as listed in the lab record.
* Host roles come from the lab description, supported by TTL and MAC evidence; no host forensics were performed.
* Severity ratings are kept at Medium as assigned, since the activity is lab-generated and no real-world impact exists.
