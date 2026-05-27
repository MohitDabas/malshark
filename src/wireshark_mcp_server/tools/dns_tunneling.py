"""
detect_dns_tunneling — entropy, volume, and record-type analysis for DNS covert channels.

Two parallel tshark passes:
  Pass 1: DNS queries  → name, type, timestamps
  Pass 2: DNS responses → name, rcode, TXT data, frame size

All analysis is grouped per apex domain (last two labels of FQDN).
"""
import asyncio
import math
import re
from collections import Counter, defaultdict
from typing import Annotated

from pydantic import Field

from ..server import mcp
from ..core import _tshark, _parse_tsv, _is_benign_domain

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# DNS record type numbers → human names
_RECORD_TYPE_NAMES: dict[str, str] = {
    "1":   "A",
    "2":   "NS",
    "5":   "CNAME",
    "6":   "SOA",
    "10":  "NULL",   # ← iodine uses this
    "12":  "PTR",
    "15":  "MX",
    "16":  "TXT",    # ← dns2tcp, DNSExfiltrator
    "28":  "AAAA",
    "33":  "SRV",
    "255": "ANY",    # ← sometimes used by tunneling tools
}

# Record types that are suspicious when seen in high volume from one domain
_TUNNEL_TYPES: frozenset[str] = frozenset({"10", "16", "255"})  # NULL, TXT, ANY

# Thresholds — tuned to keep FP rate low on real enterprise traffic
_THRESHOLDS = {
    "unique_subs_low":    10,   # elevated concern
    "unique_subs_high":   30,   # high concern
    "unique_subs_vhigh":  100,  # very high concern
    "avg_len_low":        15,   # elevated concern
    "avg_len_high":       25,   # high concern
    "avg_len_vhigh":      40,   # very high concern
    "entropy_low":        3.0,  # elevated concern
    "entropy_high":       3.5,  # high concern
    "entropy_vhigh":      4.0,  # very high concern
    "qps_low":            2.0,  # elevated query rate
    "qps_high":           5.0,  # high query rate
    "nxdomain_rate_low":  0.3,
    "nxdomain_rate_high": 0.5,
    "txt_low":            3,
    "txt_high":           10,
}


# ---------------------------------------------------------------------------
# Pure-Python helpers
# ---------------------------------------------------------------------------

def _apex_domain(fqdn: str) -> str:
    """Last two labels of an FQDN: sub.evil.com → evil.com"""
    labels = fqdn.rstrip(".").lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else fqdn.lower()


def _subdomain_prefix(fqdn: str) -> str:
    """Everything left of the apex: abc123.evil.com → abc123"""
    labels = fqdn.rstrip(".").lower().split(".")
    if len(labels) > 2:
        return ".".join(labels[:-2])
    return ""


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char. Empty string → 0.0"""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _detect_tool_signature(stats: dict) -> str:
    """
    Heuristic match against known DNS-tunnel tool patterns.
    Returns a tool name string or empty string.
    """
    null_q  = stats["null_queries"]
    txt_q   = stats["txt_queries"]
    avg_len = stats["avg_subdomain_length"]
    avg_ent = stats["avg_entropy"]
    n_uni   = stats["unique_subdomains"]

    # iodine: NULL record queries, base64-url alphabet → high entropy
    if null_q >= 5 and avg_ent > 3.5:
        return "iodine"
    # dns2tcp: TXT + CNAME heavily, long subdomains
    if txt_q >= 10 and avg_len > 30:
        return "dns2tcp"
    # dnscat2: hex-encoded labels, very long, lower entropy (hex alphabet)
    if avg_len > 40 and 2.5 < avg_ent < 3.2 and n_uni > 20:
        return "dnscat2"
    # DNSExfiltrator: base64 chunks, dots every 63 chars
    if avg_len > 50 and avg_ent > 3.8:
        return "DNSExfiltrator"
    return ""


def _score_apex(stats: dict) -> tuple[int, list[str]]:
    """
    Score a per-apex stats dict.
    Returns (score, flags).  score=0 → benign; ≥3 → suspicious; ≥6 → high-confidence tunnel.
    """
    T = _THRESHOLDS
    score = 0
    flags: list[str] = []

    n  = stats["unique_subdomains"]
    al = stats["avg_subdomain_length"]
    ae = stats["avg_entropy"]
    qp = stats["queries_per_second"]
    nr = stats["nxdomain_rate"]
    tq = stats["txt_queries"]
    nq = stats["null_queries"]

    # ── Unique subdomain count ──────────────────────────────────────────
    if n >= T["unique_subs_vhigh"]:
        score += 3; flags.append(f"VERY_HIGH_SUBDOMAIN_COUNT({n})")
    elif n >= T["unique_subs_high"]:
        score += 2; flags.append(f"HIGH_SUBDOMAIN_COUNT({n})")
    elif n >= T["unique_subs_low"]:
        score += 1; flags.append(f"ELEVATED_SUBDOMAIN_COUNT({n})")

    # ── Average subdomain length ────────────────────────────────────────
    if al >= T["avg_len_vhigh"]:
        score += 3; flags.append(f"VERY_LONG_SUBDOMAINS(avg={al:.0f}ch)")
    elif al >= T["avg_len_high"]:
        score += 2; flags.append(f"LONG_SUBDOMAINS(avg={al:.0f}ch)")
    elif al >= T["avg_len_low"]:
        score += 1; flags.append(f"ELEVATED_SUBDOMAIN_LENGTH(avg={al:.0f}ch)")

    # ── Shannon entropy ──────────────────────────────────────────────────
    if ae >= T["entropy_vhigh"]:
        score += 3; flags.append(f"VERY_HIGH_ENTROPY({ae:.2f}bits)")
    elif ae >= T["entropy_high"]:
        score += 2; flags.append(f"HIGH_ENTROPY({ae:.2f}bits)")
    elif ae >= T["entropy_low"]:
        score += 1; flags.append(f"ELEVATED_ENTROPY({ae:.2f}bits)")

    # ── Suspicious record types ──────────────────────────────────────────
    if nq > 0:
        score += 2; flags.append(f"NULL_RECORDS({nq}) ← iodine indicator")
    if tq >= T["txt_high"]:
        score += 2; flags.append(f"HIGH_TXT_QUERIES({tq})")
    elif tq >= T["txt_low"]:
        score += 1; flags.append(f"TXT_QUERIES({tq})")

    # ── Query rate ───────────────────────────────────────────────────────
    if qp >= T["qps_high"]:
        score += 2; flags.append(f"HIGH_QUERY_RATE({qp:.1f}q/s)")
    elif qp >= T["qps_low"]:
        score += 1; flags.append(f"ELEVATED_QUERY_RATE({qp:.1f}q/s)")

    # ── NXDOMAIN rate ────────────────────────────────────────────────────
    if nr >= T["nxdomain_rate_high"]:
        score += 2; flags.append(f"NXDOMAIN_STORM({nr*100:.0f}%)")
    elif nr >= T["nxdomain_rate_low"]:
        score += 1; flags.append(f"HIGH_NXDOMAIN_RATE({nr*100:.0f}%)")

    # ── Known tool signature ────────────────────────────────────────────
    tool = _detect_tool_signature(stats)
    if tool:
        score += 2; flags.append(f"KNOWN_TOOL_SIGNATURE:{tool}")

    return score, flags


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

@mcp.tool()
async def detect_dns_tunneling(
    file_path: Annotated[str, Field(description="Absolute path to a .pcap or .pcapng file")],
    min_queries: Annotated[int, Field(
        description="Minimum DNS queries to an apex domain to analyse it (default: 5)",
        ge=1,
    )] = 5,
    exclude_benign: Annotated[bool, Field(
        description="Exclude known-good domains (Microsoft, Google, CDNs). Default: True"
    )] = True,
    min_score: Annotated[int, Field(
        description="Minimum suspicion score to report (0-15). Default: 2 (low FP).",
        ge=0, le=15,
    )] = 2,
) -> str:
    """
    Detect DNS tunneling / covert C2 channels in a pcap file.

    Analyses all DNS traffic grouped by apex domain across two parallel tshark passes.

    Per-domain metrics computed:
    - Unique subdomain count  (tunneling creates many unique prefixes per session)
    - Average subdomain length (encoded data → long labels)
    - Shannon entropy          (random-looking subdomains = encoded payload)
    - Record type mix          (TXT and NULL records = tunneling-specific)
    - Query rate               (sustained high rate = data exfiltration)
    - NXDOMAIN rate            (some tools probe many non-existent subdomains)

    Known tool signatures detected: iodine, dns2tcp, dnscat2, DNSExfiltrator

    Score interpretation:
      0-1  →  normal / low-confidence indicator
      2-4  →  suspicious — manual investigation recommended
      5-7  →  likely DNS tunnel
      8+   →  high-confidence covert channel
    """
    # ── 2 parallel tshark passes ──────────────────────────────────────────
    query_raw, response_raw = await asyncio.gather(
        # Pass 1: all DNS queries
        _tshark("-r", file_path, "-Y", "dns.flags.response == 0",
                "-T", "fields",
                "-e", "frame.time_relative",
                "-e", "ip.src",
                "-e", "dns.qry.name",
                "-e", "dns.qry.type"),
        # Pass 2: all DNS responses
        _tshark("-r", file_path, "-Y", "dns.flags.response == 1",
                "-T", "fields",
                "-e", "frame.time_relative",
                "-e", "dns.qry.name",
                "-e", "dns.flags.rcode",
                "-e", "dns.txt",
                "-e", "frame.len"),
    )

    if not query_raw.strip():
        return f"No DNS traffic found in {file_path}"

    # ── Parse queries ─────────────────────────────────────────────────────
    apex_data: dict[str, dict] = {}

    def _init(apex: str) -> dict:
        return {
            "apex":               apex,
            "total_queries":      0,
            "_seen_subs":         set(),
            "_sub_lengths":       [],
            "_sub_entropies":     [],
            "unique_subdomains":  0,
            "avg_subdomain_length": 0.0,
            "avg_entropy":        0.0,
            "txt_queries":        0,
            "null_queries":       0,
            "any_queries":        0,
            "first_seen":         "",
            "last_seen":          "",
            "sample_queries":     [],    # up to 6 examples for report
            "nxdomain_count":     0,
            "response_count":     0,
            "nxdomain_rate":      0.0,
            "queries_per_second": 0.0,
            "max_response_bytes": 0,
            "txt_samples":        [],
        }

    for row in _parse_tsv(query_raw, 4):
        t, src, name, qtype = row
        if not name:
            continue
        # Skip reverse-DNS lookups — not tunneling candidates
        if name.endswith(".arpa") or name.endswith(".arpa."):
            continue
        # Skip service-discovery records (any label starting with _)
        # e.g. _dns-sd._udp.mshome.net, _ldap._tcp.example.com
        if any(label.startswith("_") for label in name.lower().split(".")):
            continue

        apex = _apex_domain(name)
        sub  = _subdomain_prefix(name)

        if exclude_benign and _is_benign_domain(apex):
            continue

        if apex not in apex_data:
            apex_data[apex] = _init(apex)

        d = apex_data[apex]
        d["total_queries"] += 1
        if not d["first_seen"]:
            d["first_seen"] = t
        d["last_seen"] = t

        # Subdomain stats (only when there IS a subdomain prefix)
        if sub:
            d["_seen_subs"].add(sub)
            d["_sub_lengths"].append(len(sub))
            d["_sub_entropies"].append(_shannon_entropy(sub))

        qtype = (qtype or "").strip()
        if qtype == "16":
            d["txt_queries"] += 1
        elif qtype == "10":
            d["null_queries"] += 1
        elif qtype == "255":
            d["any_queries"] += 1

        if len(d["sample_queries"]) < 6:
            d["sample_queries"].append({
                "t":    t,
                "name": name,
                "type": _RECORD_TYPE_NAMES.get(qtype, f"type{qtype}"),
            })

    # ── Parse responses ───────────────────────────────────────────────────
    for row in _parse_tsv(response_raw, 5):
        t, name, rcode, txt_data, frame_len = row
        if not name:
            continue
        if name.endswith(".arpa") or name.endswith(".arpa."):
            continue
        apex = _apex_domain(name)
        if apex not in apex_data:
            continue
        d = apex_data[apex]
        d["response_count"] += 1
        if rcode.strip() == "3":            # NXDOMAIN
            d["nxdomain_count"] += 1
        try:
            sz = int(frame_len)
        except (ValueError, TypeError):
            sz = 0
        if sz > d["max_response_bytes"]:
            d["max_response_bytes"] = sz
        if txt_data and len(d["txt_samples"]) < 3:
            d["txt_samples"].append(txt_data[:80])

    # ── Finalise stats and score ──────────────────────────────────────────
    results: list[dict] = []

    for apex, d in apex_data.items():
        if d["total_queries"] < min_queries:
            continue

        d["unique_subdomains"] = len(d["_seen_subs"])

        if d["_sub_lengths"]:
            d["avg_subdomain_length"] = sum(d["_sub_lengths"]) / len(d["_sub_lengths"])
        if d["_sub_entropies"]:
            d["avg_entropy"] = sum(d["_sub_entropies"]) / len(d["_sub_entropies"])
        if d["response_count"] > 0:
            d["nxdomain_rate"] = d["nxdomain_count"] / d["response_count"]

        try:
            duration = max(float(d["last_seen"]) - float(d["first_seen"]), 1.0)
            d["queries_per_second"] = d["total_queries"] / duration
        except (ValueError, ZeroDivisionError):
            d["queries_per_second"] = 0.0

        score, flags = _score_apex(d)

        if score < min_score:
            continue

        results.append({"apex": apex, "score": score, "flags": flags, "data": d})

    if not results:
        return (
            f"No DNS tunneling indicators found in {file_path}\n"
            f"  (min_score={min_score}, min_queries={min_queries})\n"
            "  Tips:\n"
            "  • Try min_score=1 to see low-confidence indicators\n"
            "  • Try exclude_benign=False to include CDN/Microsoft traffic\n"
            "  • Try min_queries=2 if the capture is short"
        )

    results.sort(key=lambda x: -x["score"])
    return _format_report(results, file_path, min_score, min_queries)


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------

def _format_report(
    results: list[dict],
    file_path: str,
    min_score: int,
    min_queries: int,
) -> str:
    w = 68
    high   = sum(1 for r in results if r["score"] >= 6)
    likely = sum(1 for r in results if 3 <= r["score"] < 6)
    poss   = sum(1 for r in results if r["score"] < 3)

    lines: list[str] = [
        "=" * w,
        "  DNS TUNNELING DETECTION REPORT",
        f"  File         : {file_path}",
        f"  Suspects     : {len(results)} domain(s)  "
        f"({high} high / {likely} likely / {poss} possible)",
        f"  Filter       : min_score≥{min_score}  min_queries≥{min_queries}",
        "=" * w,
    ]

    for idx, r in enumerate(results, 1):
        score = r["score"]
        apex  = r["apex"]
        d     = r["data"]
        flags = r["flags"]

        if score >= 6:
            verdict = "⚠⚠⚠ HIGH CONFIDENCE — likely DNS tunnel"
        elif score >= 3:
            verdict = "⚠⚠  SUSPICIOUS — investigate manually"
        else:
            verdict = "⚠   POSSIBLE — low-confidence indicator"

        lines += [
            "",
            f"{'─'*w}",
            f"  #{idx}  {apex}   score={score}   {verdict}",
            f"{'─'*w}",
            f"  Total queries     : {d['total_queries']}",
            f"  Unique subdomains : {d['unique_subdomains']}",
            f"  Avg subdomain len : {d['avg_subdomain_length']:.1f} chars",
            f"  Avg entropy       : {d['avg_entropy']:.3f} bits/char"
            + ("  (>3.5 = encoded data)" if d["avg_entropy"] > 3.5 else ""),
            f"  Query rate        : {d['queries_per_second']:.2f} q/s",
            f"  TXT queries       : {d['txt_queries']}",
            f"  NULL queries      : {d['null_queries']}"
            + ("  ← iodine indicator" if d["null_queries"] > 0 else ""),
            f"  NXDOMAIN rate     : {d['nxdomain_rate']*100:.0f}%"
            + (f"  ({d['nxdomain_count']}/{d['response_count']})" if d["response_count"] else ""),
        ]

        if d["max_response_bytes"]:
            lines.append(f"  Max resp size     : {d['max_response_bytes']} bytes"
                         + ("  ← large TXT payload" if d["max_response_bytes"] > 300 else ""))

        lines += ["", f"  Flags: {' | '.join(flags)}"]

        if d["sample_queries"]:
            lines.append("  Sample queries:")
            for q in d["sample_queries"]:
                lines.append(f"    t={q['t']:<10} [{q['type']:<10}] {q['name']}")

        if d["txt_samples"]:
            lines.append("  TXT data samples (from responses):")
            for txt in d["txt_samples"]:
                lines.append(f"    {txt}")

    lines += [
        "",
        "=" * w,
        "  Reference thresholds:",
        "    entropy >3.5 = encoded data  |  >20 unique subs = data stream",
        "    subdomain len >25 = suspicious  |  NULL records = iodine",
        "=" * w,
    ]
    return "\n".join(lines)
