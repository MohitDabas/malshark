"""Shared FastMCP application instance — imported by every tool module."""
from fastmcp import FastMCP

mcp = FastMCP(
    name="wireshark-mcp-server",
    instructions=(
        "MCP server for network forensics and malware analysis using tshark. "
        "Can extract IOCs, analyze pcap files, and capture live traffic."
    ),
)
