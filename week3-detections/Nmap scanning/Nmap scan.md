# Nmap Scan Results

Prepared by: teamXdepi
Capture date: 8 October 2026
Scanner: 192.168.40.129
Target: 192.168.40.1 (VMware MAC 00:50:56:C0:00:08, latency 0.2 to 0.7 ms)
Tool: Nmap 7.99
Ports scanned: top 1,000 TCP ports (Nmap default list)

This file summarises the result of each Nmap command run against the target. It is a results summary, not a copy of the raw console log.

## Results

| Capture | Command | Result | Nmap time |
|---|---|---|---|
| 01_syn_scan | `nmap -sS 192.168.40.1` | 3580/tcp open (nati-svrloc); 999 ports filtered (no response) | 13.87 s |
| 02_service_detection | `nmap -sV 192.168.40.1` | 3580/tcp open, identified as http: National Instruments LabVIEW service locator httpd 1.0.0; 999 ports filtered | 25.87 s |
| 03_os_detection | `nmap -O 192.168.40.1` | No exact OS match. Nmap found no closed port and gave guesses only (below) | 11.02 s |
| 04_null_scan | `nmap -sN 192.168.40.1` | All 1,000 ports open\|filtered (no response) | 21.30 s |
| 05_xmas_scan | `nmap -sX 192.168.40.1` | All 1,000 ports open\|filtered (no response) | 21.27 s |

## OS detection guesses (nmap -O)

| Guess | Confidence |
|---|---|
| Windows 11 24H2 | 92% |
| Windows 11 21H2 | 91% |
| FreeBSD 6.2 | 88% |
| Windows 10 | 86% |

Nmap reported no closed port on the target, so these guesses are low confidence.

## Notes

- Only TCP 3580 answered in any scan. The other 999 ports sent no reply, so they are reported as filtered (SYN scan) or open|filtered (NULL and XMAS scans).
- NULL and XMAS scans cannot distinguish open from filtered ports when the target sends no reply, so they did not reveal port 3580.
- The -sV scan runs Nmap's version-category scripts automatically, which is why the capture contains requests with the user agent "Nmap Scripting Engine".
- The probe times seen in the packet captures differ slightly from the Nmap times above, because the console results come from a separate run of the same commands.
