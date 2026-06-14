"""HONEYURL MCP server — exposes match_events() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json
from honeyurl.core import match_events, load_registry


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
    def honeyurl_scan(registry_path: str, records: list[dict]) -> str:
        """Match access records against a canary registry; returns JSON trip events."""
        try:
            reg = load_registry(registry_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return json.dumps({"error": str(exc)})
        events = match_events(reg, records)
        return json.dumps([e.to_dict() for e in events])

    app.run()
    return 0
