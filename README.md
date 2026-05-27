# MalShark

> **AI-powered malware traffic analysis and network forensics via the Model Context Protocol.**

A production-quality [MCP](https://modelcontextprotocol.io/) server that wraps `tshark` (Wireshark's CLI) and exposes a suite of malware analysis tools directly inside Cursor (or any MCP-compatible AI client). Ask your AI to analyze a pcap in plain English — it runs the right tools, correlates the results, and reports IOCs, C2 beacons, credential leaks, and exfiltration candidates automatically.

---

## What Makes This Different

Most pcap tools require an analyst to know exactly what to look for. This server bridges the gap:

- **MCP-native** — tools are called by the AI, not a human writing tshark filters. The AI chains calls intelligently based on what it finds.
- **Fully async and parallel** — every tool runs multiple `tshark` passes concurrently using `asyncio.gather`. A single `extract_iocs` call fans out 6 parallel tshark processes simultaneously, so analysis that would take minutes sequentially completes in seconds.
- **Malware-aware heuristics** — every detection rule was written and tuned against **real malware samples** from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net), not synthetic test cases.
- **False-positive conscious** — a curated benign-domain whitelist (CDNs, Apple, Google, Microsoft, Windows Update) keeps noise low. Every whitelist addition requires justification across two or more independent malware samples.
- **Benchmarked** — each tool version is scored against ground-truth IOC files from public malware reports. Benchmark files live in `benchmarks/`.

---

## Tools

| Tool | What it does |
|---|---|
| `pcap_summary` | High-level overview: duration, packets, victim IP, top IPs by bytes, protocol breakdown, red flags |
| `extract_iocs` | 6 parallel tshark passes → DNS queries, TLS SNI, HTTP requests/responses, **C2-on-443** (non-TLS traffic on port 443), **unreachable C2** (SYN-only), suspicious user agents |
| `find_downloads` | Detects file downloads (HTTP) and large exfil uploads; HTTPS large-transfer estimates for encrypted payloads ≥ 1 MB |
| `c2_beaconing` | Burst-cluster timing analysis on a specific IP — computes mean/median interval, jitter coefficient, and gives a confidence verdict |
| `extract_credentials` | Cleartext credentials (Basic auth, form POST, FTP, SMTP, Telnet) + malware-specific custom auth headers (e.g. `user:`, `BuildID:`) sent to bare-IP C2s |
| `http_sessions` | Full HTTP request/response pairs with cloud C2 pattern detection (Telegram Bot API, Discord/Slack webhooks, suspicious UA to whitelisted cloud domains) |
| `detect_dns_tunneling` | Entropy analysis, query length distribution, label count — scores potential DNS tunneling channels |
| `capture_packets` | Live packet capture from a network interface |
| `list_interfaces` | List available capture interfaces |

---

## Recommended Analysis Workflow

Run these in order. Each step narrows the scope for the next.

```
1. pcap_summary          ← always start here
      ↓ victim IP + red flags
2. extract_iocs          ← IOC sweep: DNS, TLS, C2-443, unreachable C2
      ↓ suspicious IPs identified
3. c2_beaconing          ← run on each suspicious IP from step 2
      ↓ beacon interval + confidence
4. find_downloads        ← what did the victim download / send out?
      ↓ file names, sizes, content types
5. http_sessions         ← full request/response detail, cloud C2 patterns
      ↓ plaintext HTTP sessions, exfil URIs
6. extract_credentials   ← any auth material in the clear?
7. detect_dns_tunneling  ← if DNS looked odd in step 2
```

With any MCP-compatible AI (Cursor, Claude Desktop, Windsurf, Continue, etc.), describe what you want in natural language:

> *"Analyze this pcap. Find the victim IP, extract all IOCs, check for beaconing, and tell me what the malware downloaded."*

The AI will chain the tools in the right order and synthesize findings into a report.

---

## Installation

**Requirements:** Python ≥ 3.11, `tshark` (Wireshark CLI) installed and on `PATH`.

```bash
# Install tshark
sudo apt install tshark          # Debian/Ubuntu
brew install wireshark           # macOS

# Clone and install
git clone https://github.com/your-username/malshark
cd malshark
pip install uv
uv sync
```

### Add to Cursor

In Cursor → Settings → MCP → Add server:

```json
{
  "mcpServers": {
    "malshark": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/malshark",
        "run",
        "wireshark-mcp"
      ]
    }
  }
}
```

Restart Cursor. The tools appear automatically in Agent mode.

---

## Quick Start

Drop your capture file into the `pcaps/` folder, then ask your AI:

```
Analyze pcaps/capture.pcap — give me the victim IP, all IOCs, and
check if there's any beaconing or file downloads.
```

Or run a specific tool:

```
Run extract_iocs on pcaps/capture.pcap
```

### Running tools directly (without Cursor)

```python
import asyncio
from src.wireshark_mcp_server.tools.summary import pcap_summary
from src.wireshark_mcp_server.tools.iocs import extract_iocs

async def main():
    print(await pcap_summary("/path/to/capture.pcap"))
    print(await extract_iocs("/path/to/capture.pcap"))

asyncio.run(main())
```

---

## Benchmarks — Tested Against Real Malware

Every tool has been validated against real-world malware captures from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net). The benchmark process:

1. **Run tools blind** — tools run on the pcap with no prior knowledge of the IOCs
2. **Load ground truth** — IOC files and malware artifacts from the official report ZIP are read
3. **Score each tool** — true positives, false positives, and misses documented
4. **Apply justified fixes** — only changes that pass a litmus test ("would this help on a clean capture? does it generalise?") are committed
5. **Document everything** — findings, gaps, and limitations written up in `benchmarks/`

### Results

| Date | Malware | Detection | Benchmark |
|---|---|---|---|
| 2026-05-08 | **macOS Shub Stealer** (ClickFix → fake cracked software) | 6/6 network-observable IOCs · 2 FPs (ad trackers from lure page) | [benchmarks/2026-05-08-ShubStealer.md](benchmarks/2026-05-08-ShubStealer.md) |
| 2026-05-11 | **macOS ClickFix Infostealer + RAT** (Google ad lure) | ~90% | inline in project_knowledge.md |
| 2026-05-22 | **SmartApeSG ClickFix → NetSupport RAT** | 87% | [benchmarks/2026-05-22-SmartApeSG.md](benchmarks/2026-05-22-SmartApeSG.md) |


---


## Project Structure

```
malshark/
├── pcaps/                   ← drop your .pcap / .pcapng files here
├── src/wireshark_mcp_server/
│   ├── core.py              # tshark runner, benign-domain list, shared helpers
│   ├── server.py            # FastMCP instance
│   ├── main.py              # entrypoint
│   └── tools/
│       ├── summary.py       # pcap_summary
│       ├── iocs.py          # extract_iocs
│       ├── beaconing.py     # c2_beaconing
│       ├── downloads.py     # find_downloads
│       ├── credentials.py   # extract_credentials
│       ├── http_sessions.py # http_sessions
│       ├── dns_tunneling.py # detect_dns_tunneling
│       └── capture.py       # capture_packets, list_interfaces
├── benchmarks/
│   ├── 2026-05-08-ShubStealer.md
│   └── 2026-05-22-SmartApeSG.md
└── pyproject.toml
```

---

## Contributing

When adding new detection rules or whitelist entries:

1. **Two-sample rule** — a domain/suffix should appear as a false positive in at least two independent captures before being whitelisted.
2. **Litmus test** — ask: *"If I ran this change on a clean capture, would it create false positives? If I skipped it on a malicious capture, would I miss the IOC?"*
3. **No overfitting** — a rule tuned to catch exactly one sample's behaviour is not generalizable. Prefer structural rules (bare IPs, suspicious TLDs, `curl` user-agents) over sample-specific ones.
4. **Document it** — add the change to the "Tool Improvements" table in `project_knowledge.md` with the sample that motivated it.

---

## Dependencies

- [FastMCP](https://github.com/jlowin/fastmcp) — MCP server framework
- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) — Wireshark CLI (must be installed separately)

---

## License

MIT
