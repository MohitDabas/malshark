"""pcap_summary, analyze_pcap_summary, read_pcap tools."""
import asyncio
import re
from collections import defaultdict
from typing import Annotated

from pydantic import Field

from ..server import mcp
from ..core import (
    _tshark, _parse_tsv,
    _is_private, _human_bytes, _human_duration,
)

# ---------------------------------------------------------------------------
# Parsing helpers for tshark statistics output
# ---------------------------------------------------------------------------

_CONV_ROW_RE = re.compile(
    r"(\S+)\s+<->\s+(\S+)\s+"
    r"(\d+)\s+[\d,.]+\s+\S+\s+"
    r"(\d+)\s+[\d,.]+\s+\S+\s+"
    r"(\d+)\s+([\d,.]+)\s+(\S+)\s+"
    r"([\d.]+)\s+"
    r"([\d.]+)"
)

_ENDPT_ROW_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(\d+)\s+"
    r"(\d+)\s+"
    r"(\d+)\s+"
    r"(\d+)\s+"
    r"(\d+)\s+"
    r"(\d+)"
)

_KNOWN_PORTS = {
    "80", "443", "8080", "8443",
    "53", "853",                       # DNS, DNS-over-TLS
    "25", "465", "587", "110", "143",  # Mail
    "22", "23",                        # SSH, Telnet
    "21",                              # FTP
    "445", "139",                      # SMB
    "3389",                            # RDP
    "3306", "5432", "1433",            # Databases
    "67", "68", "123",                 # DHCP, NTP
    "5223",                            # Apple Push Notification Service (APNS) — macOS
    "5228", "5229", "5230",            # Google FCM / Android push
    "2195", "2196",                    # Apple APNS legacy
}


def _parse_conv_tcp(raw: str, top_n: int = 8) -> list[dict]:
    results = []
    for line in raw.splitlines():
        m = _CONV_ROW_RE.search(line)
        if not m:
            continue
        ep_a, ep_b, fr_ab, fr_ba, fr_tot, b_tot, b_unit, rel_start, dur = m.groups()
        try:
            multiplier  = {"B": 1, "kB": 1024, "MB": 1024**2, "GB": 1024**3}.get(b_unit, 1)
            total_bytes = float(b_tot.replace(",", "")) * multiplier
            results.append({
                "ep_a": ep_a, "ep_b": ep_b,
                "frames": int(fr_tot), "bytes": int(total_bytes),
                "duration": float(dur), "rel_start": float(rel_start),
            })
        except (ValueError, KeyError):
            pass
    results.sort(key=lambda x: -x["bytes"])
    return results[:top_n]


def _parse_endpoints_ip(raw: str, top_n: int = 10) -> list[dict]:
    results = []
    for line in raw.splitlines():
        m = _ENDPT_ROW_RE.match(line.strip())
        if not m:
            continue
        ip, pkt_tot, b_tot, tx_pkt, tx_b, rx_pkt, rx_b = m.groups()
        results.append({
            "ip": ip, "packets": int(pkt_tot), "bytes": int(b_tot),
            "tx_bytes": int(tx_b), "rx_bytes": int(rx_b),
        })
    results.sort(key=lambda x: -x["bytes"])
    return results[:top_n]


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def pcap_summary(
    file_path: Annotated[str, Field(description="Absolute path to a .pcap or .pcapng file")],
    top_n: Annotated[int, Field(
        description="How many top talkers / conversations / ports to show (default: 10)",
        ge=3, le=30,
    )] = 10,
) -> str:
    """
    Comprehensive orientation summary for any pcap file.

    Reports in a single pass:
    - Capture duration, total packets, total bytes, average packet size, capture rate
    - Victim/infected host detection (internal IP with most traffic)
    - Protocol breakdown (top protocols by packet count with percentages)
    - Top talkers: external IPs by total bytes and packet count
    - Top destination ports: TCP and UDP separately
    - Top talker pairs (IP:port <-> IP:port) by bytes
    - Red flags: unusual ports, non-standard protocols, potential beaconing IPs

    Use this as Step 1 before running extract_iocs or find_downloads.
    """
    (
        frames_raw,
        phs_raw,
        tcp_conv_raw,
        endpoints_raw,
    ) = await asyncio.gather(
        _tshark("-r", file_path, "-T", "fields",
                "-e", "frame.time_epoch",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "frame.len",
                "-e", "_ws.col.Protocol",
                "-e", "tcp.dstport",
                "-e", "udp.dstport"),
        _tshark("-r", file_path, "-q", "-z", "io,phs"),
        _tshark("-r", file_path, "-q", "-z", "conv,tcp", "-n"),
        _tshark("-r", file_path, "-q", "-z", "endpoints,ip", "-n"),
    )

    if not frames_raw.strip():
        return f"No packets found in {file_path}"

    total_packets  = 0
    total_bytes    = 0
    first_epoch    = float("inf")
    last_epoch     = 0.0

    src_pkt_count: dict[str, int] = defaultdict(int)
    dst_pkt_count: dict[str, int] = defaultdict(int)
    proto_count:   dict[str, int] = defaultdict(int)
    tcp_dst_ports: dict[str, int] = defaultdict(int)
    udp_dst_ports: dict[str, int] = defaultdict(int)

    for row in _parse_tsv(frames_raw, 7):
        epoch_str, src, dst, length_str, proto, tcp_dport, udp_dport = row
        if not epoch_str:
            continue
        try:
            epoch  = float(epoch_str)
            length = int(length_str) if length_str else 0
        except ValueError:
            continue

        total_packets += 1
        total_bytes   += length
        if epoch < first_epoch:
            first_epoch = epoch
        if epoch > last_epoch:
            last_epoch = epoch

        if src:
            src_pkt_count[src] += 1
        if dst:
            dst_pkt_count[dst] += 1
        if proto:
            proto_count[proto] += 1
        if dst and not _is_private(dst):
            if tcp_dport:
                tcp_dst_ports[tcp_dport] += 1
            if udp_dport:
                udp_dst_ports[udp_dport] += 1

    duration   = max(last_epoch - first_epoch, 0.001)
    avg_pkt_sz = total_bytes / total_packets if total_packets else 0
    pps        = total_packets / duration
    bps        = total_bytes   / duration

    all_ips   = set(src_pkt_count) | set(dst_pkt_count)
    internals = [ip for ip in all_ips if _is_private(ip)]
    victim_ip = max(internals, key=lambda ip: src_pkt_count[ip] + dst_pkt_count[ip], default="unknown")

    endpoints     = _parse_endpoints_ip(endpoints_raw, top_n=top_n)
    ext_endpoints = [e for e in endpoints if not _is_private(e["ip"])]
    top_convs     = _parse_conv_tcp(tcp_conv_raw, top_n=top_n)
    top_protos    = sorted(proto_count.items(), key=lambda x: -x[1])[:top_n]
    top_tcp_ports = sorted(tcp_dst_ports.items(), key=lambda x: -x[1])[:10]
    top_udp_ports = sorted(udp_dst_ports.items(), key=lambda x: -x[1])[:8]

    unusual_tcp = [
        (port, cnt) for port, cnt in top_tcp_ports
        if port not in _KNOWN_PORTS and int(port) > 1024
    ]

    beacon_candidates: list[tuple[str, float]] = []
    for ip, cnt in src_pkt_count.items():
        if _is_private(ip):
            continue
        ip_pps = cnt / duration
        if ip_pps > 5.0:
            beacon_candidates.append((ip, ip_pps))
    beacon_candidates.sort(key=lambda x: -x[1])

    w = 66
    lines: list[str] = [
        "=" * w,
        "  PCAP SUMMARY",
        f"  File      : {file_path}",
        f"  Duration  : {_human_duration(duration)}  ({duration:.1f}s)",
        f"  Packets   : {total_packets:,}",
        f"  Bytes     : {_human_bytes(total_bytes)}",
        f"  Avg size  : {avg_pkt_sz:.0f}B/pkt",
        f"  Rate      : {pps:.1f} pkt/s  |  {_human_bytes(int(bps))}/s",
        f"  Victim    : {victim_ip}  (most active internal host)",
        "=" * w,
    ]

    lines += ["", f"[PROTOCOLS]  top {len(top_protos)} by packet count"]
    for proto, cnt in top_protos:
        pct = cnt / total_packets * 100
        bar = "█" * int(pct / 2)
        lines.append(f"  {proto:<18} {cnt:>7,}  {pct:5.1f}%  {bar}")

    if ext_endpoints:
        lines += ["", "[TOP EXTERNAL IPs]  by total bytes"]
        lines.append(f"  {'IP':<20} {'Pkts':>8}  {'Total':>9}  {'Sent':>9}  {'Rcvd':>9}")
        lines.append("  " + "-" * 60)
        for e in ext_endpoints[:top_n]:
            lines.append(
                f"  {e['ip']:<20} {e['packets']:>8,}  "
                f"{_human_bytes(e['bytes']):>9}  "
                f"{_human_bytes(e['tx_bytes']):>9}  "
                f"{_human_bytes(e['rx_bytes']):>9}"
            )

    if top_convs:
        lines += ["", "[TOP TCP CONVERSATIONS]  by bytes"]
        for conv in top_convs:
            dur_str = _human_duration(conv["duration"])
            lines.append(f"  {conv['ep_a']:<28} <-> {conv['ep_b']:<28}")
            lines.append(
                f"      {_human_bytes(conv['bytes']):>9}  "
                f"{conv['frames']:>7,} pkts  "
                f"dur={dur_str}  "
                f"t+{conv['rel_start']:.1f}s"
            )

    if top_tcp_ports:
        lines += ["", "[TOP TCP DESTINATION PORTS]"]
        for port, cnt in top_tcp_ports:
            flag = "  ← unusual" if (port not in _KNOWN_PORTS and int(port) > 1024) else ""
            lines.append(f"  :{port:<7} {cnt:>7,} pkts{flag}")

    if top_udp_ports:
        lines += ["", "[TOP UDP DESTINATION PORTS]"]
        for port, cnt in top_udp_ports:
            lines.append(f"  :{port:<7} {cnt:>7,} pkts")

    red_flags: list[str] = []
    if unusual_tcp:
        for port, cnt in unusual_tcp[:5]:
            red_flags.append(f"Non-standard TCP port :{port} has {cnt:,} packets")
    if beacon_candidates:
        for ip, ip_pps in beacon_candidates[:5]:
            red_flags.append(
                f"High packet rate from {ip}: {ip_pps:.1f} pkt/s "
                f"(possible beaconing — run c2_beaconing)"
            )
    if red_flags:
        lines += ["", "⚠  RED FLAGS"]
        for flag in red_flags:
            lines.append(f"  • {flag}")

    if phs_raw.strip():
        phs_lines = [
            ln for ln in phs_raw.splitlines()
            if ln.strip() and not ln.startswith("===") and not ln.startswith("Filter")
            and "Protocol Hierarchy" not in ln
        ]
        if phs_lines:
            lines += ["", "[PROTOCOL HIERARCHY TREE]"]
            lines.extend("  " + ln for ln in phs_lines[:30])

    lines += ["", "=" * w]
    lines.append("  Next steps: extract_iocs → find_downloads → c2_beaconing")
    lines.append("=" * w)
    return "\n".join(lines)


@mcp.tool()
async def read_pcap(
    file_path: Annotated[str, Field(description="Absolute path to a .pcap or .pcapng file")],
    display_filter: Annotated[str, Field(
        description="Wireshark display filter (e.g. 'tcp.port==80', 'http', 'ip.addr==1.2.3.4')"
    )] = "",
    packet_count: Annotated[int, Field(description="Max packets to show", ge=1, le=1000)] = 50,
) -> str:
    """Read packets from a .pcap/.pcapng file and show a human-readable summary."""
    args = ["-r", file_path, "-c", str(packet_count)]
    if display_filter:
        args += ["-Y", display_filter]
    args += [
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_relative",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "frame.len",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    ]
    raw = await _tshark(*args)
    if not raw.strip():
        return f"No packets found in {file_path}" + (f" matching '{display_filter}'" if display_filter else "")

    lines = [f"Packets from {file_path}" + (f" filter='{display_filter}'" if display_filter else ""), ""]
    for row in _parse_tsv(raw, 11):
        num, rel, src, dst, tsrc, tdst, usrc, udst, length, proto, info = row
        sport = tsrc or usrc
        dport = tdst or udst
        conn = f"{src}:{sport} → {dst}:{dport}" if src and dst else (src or dst or "")
        lines.append(f"#{num:<6} t={rel:<10} {proto:<8} {conn:<42} len={length}  {info[:60]}")
    return "\n".join(lines)


@mcp.tool()
async def analyze_pcap_summary(
    file_path: Annotated[str, Field(description="Absolute path to a .pcap or .pcapng file")],
) -> str:
    """Statistical summary of a pcap: protocol hierarchy, top talkers, duration."""
    phs_raw, conv_raw = await asyncio.gather(
        _tshark("-r", file_path, "-q", "-z", "io,phs"),
        _tshark("-r", file_path, "-q", "-z", "conv,ip"),
    )
    return f"=== Protocol Hierarchy ===\n{phs_raw}\n\n=== IP Conversations ===\n{conv_raw}"
