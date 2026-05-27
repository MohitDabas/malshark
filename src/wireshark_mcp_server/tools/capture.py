"""list_interfaces and capture_packets (live capture) tools."""
from typing import Annotated

from pydantic import Field

from ..server import mcp
from ..core import _tshark, _parse_tsv


@mcp.tool()
async def list_interfaces() -> str:
    """List available network interfaces for live packet capture."""
    raw = await _tshark("-D")
    return f"Available interfaces:\n{raw.strip()}" if raw.strip() else "No interfaces found."


@mcp.tool()
async def capture_packets(
    interface: Annotated[str, Field(description="Network interface (e.g. eth0, wlan0)")] = "eth0",
    packet_count: Annotated[int, Field(description="Number of packets to capture", ge=1, le=500)] = 10,
    display_filter: Annotated[str, Field(description="Capture filter (e.g. 'tcp port 80')")] = "",
    timeout: Annotated[int, Field(description="Max seconds to wait", ge=1, le=120)] = 30,
) -> str:
    """Capture live packets from a network interface using tshark."""
    args = [
        "-i", interface,
        "-c", str(packet_count),
        "-T", "fields",
        "-e", "frame.number", "-e", "frame.time_relative",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "frame.len", "-e", "_ws.col.Protocol", "-e", "_ws.col.Info",
    ]
    if display_filter:
        args += ["-f", display_filter]

    raw = await _tshark(*args, timeout=timeout)
    if not raw.strip():
        return "No packets captured. Check interface name or run with root privileges."

    lines = [f"Live capture on {interface} ({packet_count} packets requested):", ""]
    for row in _parse_tsv(raw, 9):
        num, rel, src, dst, tsrc, tdst, length, proto, info = row
        conn = f"{src}:{tsrc} → {dst}:{tdst}" if src and dst else ""
        lines.append(f"#{num:<5} t={rel:<10} {proto:<8} {conn:<42} len={length}  {info[:50]}")
    return "\n".join(lines)
