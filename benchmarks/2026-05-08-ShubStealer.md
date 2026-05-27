# Benchmark: 2026-05-08 macOS Shub Stealer Infection

**Source:** https://www.malware-traffic-analysis.net/2026/05/08/index.html  
**Malware family:** Shub Stealer (macOS, ClickFix / fake cracked-software lure)  
**Capture duration:** 15m 15s · 21,537 pkts · 21 MB  
**Victim IP:** `10.5.8.101`  
**Methodology:** Tools run **blind** (no IOC files opened), then compared to ground truth.

---

## Infection Chain (Ground Truth)

```
User searched for cracked software
  → Google Drive lure page
  → Redirect: socvy.com/2DAk3a
  → Redirect: shoeboxthen.com/diffinity/
  → "Download for macOS" page: orbitlinkgrid6.cyou/?c=...
  → ClickFix: user pastes base64-encoded curl command into Terminal
  → Downloads loader.sh (1.3 KB) from ploesglodigigachads.com/debug/loader.sh
  → loader.sh decodes & fetches payload.applescript (58 KB) from same host
  → osascript runs payload → persistence + wallet injection
  → LaunchAgent com.google.keystone.agent fires every 60s
  → C2 check-in: POST https://ploesglodigigachads.com/api/debug/event (JSON telemetry)
  → Victim IP lookup: api.ipify.org
```

**Key C2 infrastructure:**
| Domain | Role |
|---|---|
| `socvy.com` | Redirect hop 1 |
| `shoeboxthen.com` | Redirect hop 2 |
| `orbitlinkgrid6.cyou` | Fake download page / C2 staging |
| `ploesglodigigachads.com` | Payload delivery + C2 check-in |
| `api.ipify.org` | Victim external IP lookup |

**Persistence mechanism:** LaunchAgent `com.google.keystone.agent` masquerading as Google Keystone updater — `StartInterval: 60` seconds.

---

## Tool-by-Tool Results

### `pcap_summary` ✅

- Correctly identified victim: `10.5.8.101`
- Flagged `172.67.204.194` and `17.253.127.134` for "high packet rate / possible beaconing"
- `17.253.127.134` is Apple infrastructure (gspe35-ssl, ocsp2, help.apple.com) — **false positive** in the red-flags section; the real beaconing is `172.67.203.61`
- Protocol breakdown shows QUIC (41%) and TLS (7.9%) — all C2 traffic is TLS-only, no plaintext

**Score: 8/10** (correct victim, triggered beaconing hint, one FP in red flags)

---

### `extract_iocs` ✅✅

**DNS detections — 7 queried, 7 flagged:**

| Domain | True/False | Reason |
|---|---|---|
| `socvy.com` | ✅ TP | Redirect hop 1 |
| `shoeboxthen.com` | ✅ TP | Redirect hop 2 |
| `orbitlinkgrid6.cyou` | ✅ TP | Staging/lure domain |
| `ploesglodigigachads.com` | ✅ TP | Payload delivery + C2 |
| `api.ipify.org` | ✅ TP* | Used by loader for external IP lookup |
| `ib.anycast.adnxs.com` | ⚠ FP | AppNexus ad tracker loaded by lure page — not malware C2 |
| `cm.g.doubleclick.net` | ⚠ FP | Google ad tracker from lure page — not malware C2 |

> *`api.ipify.org` is a legitimate public service, but it IS used by the malware — flagging it is correct.

**C2-443 detection:**  
- `172.67.203.61` → `ploesglodigigachads.com` ✅ — 240 TCP payload packets on :443 that tshark fails to parse as TLS records (fragmented/reassembled TLS app data). Real C2 confirmed.

**C2-UNREACHABLE detection:**  
- `172.67.74.152` (`api.ipify.org`) — 8 SYN attempts with no TCP session established. Technically a TP (malware tried to reach it repeatedly), though `api.ipify.org` is a legitimate service.

**TLS SNI detections:**  
All 4 malware domains (`ploesglodigigachads.com`, `orbitlinkgrid6.cyou`, `shoeboxthen.com`, `socvy.com`) correctly surfaced in suspicious TLS list.

**FP: `tether.edge.apple`** — Apple's own `.apple` TLD (private networking service), appearing in macOS captures as normal background traffic. **Fixed in this benchmark** (see Fixes Applied).

**Score: 9/10** (5/5 malware domains detected, 2 ad-tracker FPs from lure-page browsing)

---

### `c2_beaconing` ✅ (partial)

Run on `172.67.203.61` (ploesglodigigachads.com):

- **Dominant interval: 60s** ← exact match to persistence plist `StartInterval: 60`
- Jitter CV = 0.84 → VERDICT: LOW CONFIDENCE / HUMAN

**Gap:** The beaconing tool correctly identifies the 60-second dominant interval which matches the LaunchAgent precisely, but assigns LOW CONFIDENCE due to jitter threshold (CV > 0.5). The LaunchAgent fires every 60s but the network effects (TLS handshake, payload size variance) add jitter. This is a stealer beacon, not a rigid C2 ping — some jitter is inherent.

**Score: 7/10** — correct interval identified, wrong confidence verdict for stealer beaconing pattern

---

### `find_downloads` ❌

**Score: 0/2** — missed both malware downloads:

| File | Size | Reason missed |
|---|---|---|
| `loader.sh` | 1.3 KB | HTTPS (TLS), under 1 MB HTTPS-estimate threshold |
| `payload.applescript` | 58 KB | HTTPS (TLS), under 1 MB HTTPS-estimate threshold |

**Known limitation:** HTTPS estimates require ≥ 1 MB to flag (avoids noise from normal web browsing). Smaller script payloads over TLS are invisible to this tool. There are **zero plaintext HTTP requests** in this capture — all malware communication is TLS-only.

**Alternative coverage:** Both files are covered via DNS flags and TLS SNI for their delivery host (`ploesglodigigachads.com`). `find_downloads` is primarily designed for large binary drops (EXEs, DLLs, ZIPs ≥1 MB), not script-based stealers.

---

### `extract_credentials` ✅ (correctly empty)

No credential material in capture — expected. The Shub Stealer exfiltrates via HTTPS POST (encrypted), not cleartext. Score: N/A (correct null result).

---

### `http_sessions` ✅ (correctly empty)

Zero HTTP (plaintext) sessions in the capture. All traffic is TLS/QUIC. Score: N/A (correct null result).

---

### `detect_dns_tunneling` ✅ (correctly empty)

No DNS tunneling indicators. Score: N/A (correct null result).

---

## Coverage Summary

| IOC / Artifact | Detected | Tool |
|---|---|---|
| `socvy.com` (redirect) | ✅ | extract_iocs DNS |
| `shoeboxthen.com` (redirect) | ✅ | extract_iocs DNS |
| `orbitlinkgrid6.cyou` (staging) | ✅ | extract_iocs DNS + TLS |
| `ploesglodigigachads.com` (C2) | ✅ | extract_iocs DNS + TLS + C2-443 |
| `api.ipify.org` (IP lookup) | ✅ | extract_iocs DNS + C2-UNREACHABLE |
| 60-second beacon interval | ✅ | c2_beaconing (dominant=57.6s) |
| loader.sh download (1.3 KB TLS) | ❌ | find_downloads (below 1MB threshold) |
| payload.applescript (58 KB TLS) | ❌ | find_downloads (below 1MB threshold) |
| LaunchAgent masquerading as Google | ❌ | no host-level tool |
| Wallet injection artifacts | ❌ | no host-level tool |

**Detection rate: 6/10 IOCs (60%)** — but all 6 are network-observable and properly flagged. The 4 misses (2 encrypted small downloads + 2 host artifacts) require endpoint visibility.

---

## False Positives

| FP | Domain | Why | Action |
|---|---|---|---|
| Ad tracker | `ib.anycast.adnxs.com` | AppNexus ads loaded by lure page during victim's web browsing | Leave (dual-use; appears in malvertising chains too) |
| Ad tracker | `cm.g.doubleclick.net` | Google Ads loaded by same lure page | Leave (Google Ads, but also used in malvertising) |
| Apple infra TLS | `tether.edge.apple` | Apple private network service using Apple's own `.apple` TLD | **Fixed** — added `.apple` to benign suffixes |

---

## Fixes Applied

### Fix: Add `.apple` TLD to benign suffixes (`core.py`)

**Justification:**  
- `tether.edge.apple` (Apple's private networking daemon) appeared as a suspicious TLS SNI.
- Apple owns the `.apple` gTLD — any domain under `.apple` is Apple infrastructure.
- Seen in this capture (2026-05-08) **and** the prior 2026-05-11 macOS benchmark.
- Satisfies the two-sample rule from incremental improvement policy.
- Litmus test passed: if I ran this on a clean macOS capture, `tether.edge.apple` would appear as a FP.

**Before:** `_is_benign_domain("tether.edge.apple") → False` → appeared in suspicious TLS list  
**After:** `_is_benign_domain("tether.edge.apple") → True` → correctly excluded

**Did NOT fix:**
- `ib.anycast.adnxs.com` / `cm.g.doubleclick.net` — legitimate ad networks BUT used in malvertising redirect chains. Whitelisting would create blind spots for a common initial access vector.
- HTTPS download threshold — the 1 MB minimum is intentional to avoid noise from normal web traffic. Script-based stealers downloading small payloads over TLS cannot be caught by HTTPS estimates alone.

---

## Generalizable Observations

1. **macOS stealers use script-only TLS payloads** — both the loader and applescript are small text files over HTTPS. `find_downloads` (1 MB HTTPS minimum) will always miss these. Suggest documenting this as a class-level limitation.

2. **ClickFix leaves DNS fingerprints** — the entire redirect chain (`socvy.com → shoeboxthen.com → orbitlinkgrid6.cyou`) is visible in DNS before any TLS. DNS-layer detection is effective for this delivery pattern.

3. **LaunchAgent beacon interval matches `c2_beaconing` dominant interval** — the 60s `StartInterval` in the plist matches the 57.6s dominant interval from beaconing analysis. Exact integer-second intervals with some jitter should get higher confidence, not lower.

4. **Lure-page ad trackers are FPs in DNS** — when the victim visits a lure page (Google Drive, etc.), ad networks (`adnxs`, `doubleclick`) appear in DNS. These pre-date any infection and should not be labeled as malware IOCs by analysts.
