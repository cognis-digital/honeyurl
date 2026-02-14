"""HONEYURL MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from honeyurl.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-honeyurl[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-honeyurl[mcp]'")
        return 1
    app = FastMCP("honeyurl")

    @app.tool()
    def honeyurl_scan(target: str) -> str:
        """Generate canary URLs/tokens + a matcher for trip events. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
