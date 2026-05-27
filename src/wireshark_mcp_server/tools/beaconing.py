"""c2_beaconing — burst-clustering beacon interval analysis."""
import asyncio
import statistics
from collections import Counter
from typing import Annotated

from pydantic import Field

from ..server import mcp
from ..core import _tshark, _parse_tsv, _human_bytes, _human_duration


@mcp.tool()
async def c2_beaconing(
    file_path: Annotated[str, Field(description="Absolute path to a .pcap or .pcapng file")],
    target_ip: Annotated[str, Field(description="The suspected C2 IP address to analyze")],
    burst_gap_threshold: Annotated[float, Field(
        description="Seconds of silence that separates two bursts of activity (default: 2.0)",
        ge=0.1, le=60.0,
    )] = 2.0,
    idle_gap_threshold: Annotated[float, Field(
        description="Gaps larger than this (seconds) are treated as idle/reconnect, not beacon interval (default: 300)",
        ge=10.0, le=3600.0,
    )] = 300.0,
) -> str:
    """
    Analyze packet timing between the victim and a target IP to detect C2 beaconing.

    Beaconing is when malware calls home at regular intervals. This tool:
    - Collects all packet timestamps to/from the target IP
    - Groups them into activity bursts (packets within burst_gap_threshold of each other)
    - Measures the interval between consecutive burst starts
    - Computes: mean interval, median, stdev, jitter coefficient (stdev/mean)
    - Classifies confidence: jitter < 0.10 = very regular, < 0.30 = likely beacon
    - Also reports TCP connection count, total data volume, and active duration
    """
    outbound_filter = f"ip.dst == {target_ip}"
    inbound_filter  = f"ip.src == {target_ip}"
    syn_filter      = f"ip.dst == {target_ip} && tcp.flags.syn == 1 && tcp.flags.ack == 0"

    outbound_raw, inbound_raw, syn_raw = await asyncio.gather(
        _tshark("-r", file_path, "-Y", outbound_filter,
                "-T", "fields", "-e", "frame.time_epoch", "-e", "frame.len",
                "-e", "tcp.dstport"),
        _tshark("-r", file_path, "-Y", inbound_filter,
                "-T", "fields", "-e", "frame.time_epoch", "-e", "frame.len"),
        _tshark("-r", file_path, "-Y", syn_filter,
                "-T", "fields", "-e", "frame.time_epoch", "-e", "tcp.dstport"),
    )

    if not outbound_raw.strip() and not inbound_raw.strip():
        return f"No traffic found to/from {target_ip} in {file_path}"

    out_packets: list[tuple[float, int, str]] = []
    for row in _parse_tsv(outbound_raw, 3):
        ts_str, length_str, port = row
        try:
            out_packets.append((float(ts_str), int(length_str), port))
        except ValueError:
            pass

    in_packets: list[tuple[float, int]] = []
    for row in _parse_tsv(inbound_raw, 2):
        ts_str, length_str = row
        try:
            in_packets.append((float(ts_str), int(length_str)))
        except ValueError:
            pass

    syn_times: list[float] = []
    dest_ports: list[str] = []
    for row in _parse_tsv(syn_raw, 2):
        ts_str, port = row
        try:
            syn_times.append(float(ts_str))
            if port:
                dest_ports.append(port)
        except ValueError:
            pass

    if not out_packets:
        return f"No outbound traffic from victim to {target_ip} found."

    out_packets.sort(key=lambda x: x[0])
    in_packets.sort(key=lambda x: x[0])

    out_timestamps    = [p[0] for p in out_packets]
    total_out_bytes   = sum(p[1] for p in out_packets)
    total_in_bytes    = sum(p[1] for p in in_packets)
    total_bytes       = total_out_bytes + total_in_bytes
    active_duration   = out_timestamps[-1] - out_timestamps[0] if len(out_timestamps) > 1 else 0

    port_counts = Counter(p[2] for p in out_packets if p[2])
    top_ports   = port_counts.most_common(5)

    # Burst detection
    bursts: list[tuple[float, int, int]] = []
    burst_start  = out_timestamps[0]
    burst_pkts   = 1
    burst_bytes  = out_packets[0][1]

    for i in range(1, len(out_timestamps)):
        gap = out_timestamps[i] - out_timestamps[i - 1]
        if gap <= burst_gap_threshold:
            burst_pkts  += 1
            burst_bytes += out_packets[i][1]
        else:
            bursts.append((burst_start, burst_pkts, burst_bytes))
            burst_start  = out_timestamps[i]
            burst_pkts   = 1
            burst_bytes  = out_packets[i][1]
    bursts.append((burst_start, burst_pkts, burst_bytes))

    burst_starts     = [b[0] for b in bursts]
    raw_intervals    = [burst_starts[i + 1] - burst_starts[i] for i in range(len(burst_starts) - 1)]
    beacon_intervals = [iv for iv in raw_intervals if iv <= idle_gap_threshold]
    idle_gaps        = [iv for iv in raw_intervals if iv >  idle_gap_threshold]

    syn_intervals: list[float] = []
    if len(syn_times) >= 2:
        syn_times.sort()
        syn_intervals = [syn_times[i + 1] - syn_times[i] for i in range(len(syn_times) - 1)]
        syn_intervals = [iv for iv in syn_intervals if iv <= idle_gap_threshold]

    def _stats(intervals: list[float]) -> dict:
        if len(intervals) < 2:
            return {}
        mean_iv   = statistics.mean(intervals)
        median_iv = statistics.median(intervals)
        stdev_iv  = statistics.stdev(intervals)
        jitter    = stdev_iv / mean_iv if mean_iv > 0 else float("inf")
        bucket    = max(0.5, round(mean_iv * 0.1, 1))
        counts: Counter = Counter(round(iv / bucket) * bucket for iv in intervals)
        dominant  = counts.most_common(1)[0][0]
        return {
            "count":               len(intervals),
            "mean_s":              round(mean_iv,   3),
            "median_s":            round(median_iv, 3),
            "stdev_s":             round(stdev_iv,  3),
            "jitter":              round(jitter,    4),
            "min_s":               round(min(intervals), 3),
            "max_s":               round(max(intervals), 3),
            "dominant_interval_s": dominant,
        }

    def _classify(jitter: float) -> str:
        if   jitter < 0.10: return "HIGH CONFIDENCE BEACON  (jitter < 10% — very regular)"
        elif jitter < 0.25: return "LIKELY BEACON            (jitter 10-25%)"
        elif jitter < 0.50: return "POSSIBLE BEACON          (jitter 25-50%)"
        else:               return "LOW CONFIDENCE / HUMAN   (jitter > 50% — irregular)"

    burst_stats = _stats(beacon_intervals)
    syn_stats   = _stats(syn_intervals)

    lines: list[str] = [
        "=" * 62,
        "  C2 BEACONING ANALYSIS",
        f"  File      : {file_path}",
        f"  Target IP : {target_ip}",
        "=" * 62,
        "",
        "── TRAFFIC OVERVIEW ────────────────────────────────────",
        f"  Outbound packets  : {len(out_packets)}",
        f"  Inbound packets   : {len(in_packets)}",
        f"  Outbound bytes    : {_human_bytes(total_out_bytes)}",
        f"  Inbound bytes     : {_human_bytes(total_in_bytes)}",
        f"  Total data        : {_human_bytes(total_bytes)}",
        f"  Active duration   : {_human_duration(active_duration)}",
        f"  Top ports         : {', '.join(f'{p}({c})' for p,c in top_ports)}",
        "",
        "── BURST ANALYSIS ──────────────────────────────────────",
        f"  Burst gap threshold  : {burst_gap_threshold}s  "
        f"(packets within this window = same burst)",
        f"  Bursts detected      : {len(bursts)}",
        f"  Idle gaps (>{idle_gap_threshold}s)  : {len(idle_gaps)}"
        + (f"  [max {round(max(idle_gaps),1)}s]" if idle_gaps else ""),
        f"  Beacon intervals     : {len(beacon_intervals)}",
    ]

    if burst_stats:
        lines += [
            "",
            "── BURST-INTERVAL STATISTICS ───────────────────────────",
            f"  Mean interval     : {burst_stats['mean_s']} s",
            f"  Median interval   : {burst_stats['median_s']} s",
            f"  Std deviation     : {burst_stats['stdev_s']} s",
            f"  Jitter (CV)       : {burst_stats['jitter']}  "
            f"({'low = regular' if burst_stats['jitter'] < 0.3 else 'high = irregular'})",
            f"  Min / Max         : {burst_stats['min_s']}s  /  {burst_stats['max_s']}s",
            f"  Dominant interval : {burst_stats['dominant_interval_s']} s",
            "",
            f"  ► VERDICT: {_classify(burst_stats['jitter'])}",
        ]
    else:
        lines.append("\n  Not enough bursts for interval statistics.")

    if syn_stats:
        lines += [
            "",
            "── TCP CONNECTION BEACONING ────────────────────────────",
            f"  TCP SYN packets      : {len(syn_times)}",
            f"  Connection intervals : {syn_stats['count']}",
            f"  Mean conn interval   : {syn_stats['mean_s']} s",
            f"  Jitter (CV)          : {syn_stats['jitter']}",
            f"  Dominant interval    : {syn_stats['dominant_interval_s']} s",
            f"  ► VERDICT: {_classify(syn_stats['jitter'])}",
        ]
    elif syn_times:
        lines += [
            "",
            "── TCP CONNECTION BEACONING ────────────────────────────",
            f"  TCP SYN packets : {len(syn_times)}  (single persistent connection)",
        ]

    if bursts:
        lines += [
            "",
            "── BURST TIMELINE (first 20) ───────────────────────────",
            f"  {'Time':>12}   {'Pkts':>5}   {'Bytes':>8}   {'Interval from prev':>20}",
        ]
        first_epoch = bursts[0][0]
        for idx, (bstart, bpkts, bbytes) in enumerate(bursts[:20]):
            rel = round(bstart - first_epoch, 2)
            prev_interval = f"{round(bstart - bursts[idx-1][0], 2)}s" if idx > 0 else "—"
            lines.append(
                f"  {rel:>12.2f}s   {bpkts:>5}   "
                f"{_human_bytes(bbytes):>8}   {prev_interval:>20}"
            )
        if len(bursts) > 20:
            lines.append(f"  ... and {len(bursts) - 20} more bursts")

    return "\n".join(lines)
