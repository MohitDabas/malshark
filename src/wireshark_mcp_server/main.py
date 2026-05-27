"""
Wireshark MCP Server — entry point.

Architecture:
  server.py   — FastMCP instance
  core.py     — constants, async tshark runner, shared helpers
  tools/      — one module per tool; importing the package registers all @mcp.tool()s
"""
from .server import mcp
from . import tools as _tools  # side-effect: registers all tool decorators  # noqa: F401


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
