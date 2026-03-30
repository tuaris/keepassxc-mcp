"""KeePassXC MCP server — pure Python implementation.

Exposes KeePassXC browser protocol operations as MCP tools via the
MCP stdio transport (JSON-RPC 2.0 over stdin/stdout).  No external MCP
SDK required — the protocol is simple enough to implement directly.
"""
from __future__ import annotations

import json
import os
import sys

from .client import KPXCClient, detect_socket_path, log

PROTOCOL_VERSION = "2024-11-05"

_client: KPXCClient | None = None


def _get_client() -> KPXCClient:
    """Lazy-init the KeePassXC protocol client."""
    global _client
    if _client is not None:
        return _client

    host = os.environ.get("KEEPASSXC_HOST")
    port = os.environ.get("KEEPASSXC_PORT")
    socket_path = os.environ.get("KEEPASSXC_SOCKET")
    timeout = int(os.environ.get("KEEPASSXC_TIMEOUT", "30000")) / 1000

    if host:
        _client = KPXCClient(host=host, port=int(port or 19455),
                             timeout=timeout)
        log(f"Target: TCP {host}:{port or 19455}")
    else:
        if not socket_path:
            socket_path = detect_socket_path()
        if socket_path:
            _client = KPXCClient(socket_path=socket_path, timeout=timeout)
            log(f"Target: socket {socket_path}")
        else:
            _client = KPXCClient(host="127.0.0.1",
                                 port=int(port or 19455),
                                 timeout=timeout)
            log(f"Target: TCP 127.0.0.1:{port or 19455} (no socket found)")

    return _client


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

def _read_message():
    """Read one JSON-RPC message from stdin."""
    line = sys.stdin.readline()
    if not line:
        return None
    return json.loads(line.strip())


def _write_message(msg: dict):
    """Write one JSON-RPC message to stdout."""
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _result(msg_id, result: dict):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code: int, message: str):
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message}}


def _tool_result(text: str):
    return {"content": [{"type": "text", "text": text}]}


def _tool_error(text: str):
    return {"content": [{"type": "text", "text": text}], "isError": True}


# ---------------------------------------------------------------------------
# Tool catalogue
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "get_logins",
        "description":
            "Retrieve saved credentials (username + password) from KeePassXC "
            "for a given URL. Returns all matching entries including login, "
            "password, name, and UUID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description":
                        "URL to look up credentials for "
                        "(e.g. https://example.com)",
                },
                "submitUrl": {
                    "type": "string",
                    "description":
                        "Optional form submit URL for more specific matching",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "get_totp",
        "description":
            "Get the current TOTP (time-based one-time password) code for a "
            "KeePassXC entry. Requires the entry UUID (obtain via get_logins "
            "first).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "uuid": {
                    "type": "string",
                    "description": "UUID of the KeePassXC entry",
                },
            },
            "required": ["uuid"],
        },
    },
    {
        "name": "set_login",
        "description":
            "Save or update credentials in KeePassXC. "
            "To update an existing entry, provide its uuid.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string",
                        "description": "URL for the credential"},
                "login": {"type": "string",
                          "description": "Username / login"},
                "password": {"type": "string",
                             "description": "Password"},
                "submitUrl": {"type": "string",
                              "description": "Form submit URL"},
                "group": {"type": "string",
                          "description": "Target group name"},
                "groupUuid": {"type": "string",
                              "description": "Target group UUID"},
                "uuid": {"type": "string",
                         "description":
                             "Entry UUID (for updating an existing entry)"},
            },
            "required": ["url", "login", "password"],
        },
    },
    {
        "name": "generate_password",
        "description":
            "Generate a random password using KeePassXC's password generator. "
            "Note: this may open the KeePassXC password generator dialog on "
            "the host and wait for the user to confirm.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "lock_database",
        "description": "Lock the currently open KeePassXC database.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_database_groups",
        "description":
            "List all groups (folders) in the KeePassXC database as a tree.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_database_hash",
        "description":
            "Get the SHA-256 hash of the current KeePassXC database. "
            "Useful for detecting if the database has changed.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "associate",
        "description":
            "Manually (re-)associate this MCP server with the KeePassXC "
            "database. A confirmation dialog will appear in KeePassXC. "
            "Usually not needed — association happens automatically on "
            "first use.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

def _dispatch_tool(name: str, args: dict) -> dict:
    """Execute a tool and return a content result dict."""
    try:
        if name == "get_logins":
            result = _get_client().get_logins(
                args["url"], args.get("submitUrl") or None)
            entries = result.get("entries", [])
            if not entries:
                return _tool_result("No credentials found for this URL.")
            lines = []
            for i, e in enumerate(entries, 1):
                parts = [
                    f"Entry {i}:",
                    f"  Name: {e.get('name', 'N/A')}",
                    f"  Login: {e.get('login', 'N/A')}",
                    f"  Password: {e.get('password', 'N/A')}",
                    f"  UUID: {e.get('uuid', 'N/A')}",
                ]
                if e.get("expired") == "true":
                    parts.append("  WARNING: expired")
                if e.get("totp"):
                    parts.append(f"  TOTP: {e['totp']}")
                if e.get("stringFields"):
                    fields = ", ".join(
                        f"{k}={v}" for f in e["stringFields"]
                        for k, v in f.items())
                    parts.append(f"  Custom fields: {fields}")
                lines.append("\n".join(parts))
            text = (f"Found {len(entries)} credential(s):\n\n"
                    + "\n\n".join(lines))
            return _tool_result(text)

        elif name == "get_totp":
            result = _get_client().get_totp(args["uuid"])
            return _tool_result(f"TOTP: {result.get('totp', 'N/A')}")

        elif name == "set_login":
            params: dict = {
                "url": args["url"],
                "login": args["login"],
                "password": args["password"],
            }
            for key in ("submitUrl", "group", "groupUuid", "uuid"):
                if args.get(key):
                    params[key] = args[key]
            result = _get_client().set_login(params)
            if result.get("success") == "true":
                return _tool_result("Credentials saved successfully.")
            return _tool_result(f"Result: {json.dumps(result)}")

        elif name == "generate_password":
            result = _get_client().generate_password()
            return _tool_result(
                f"Generated password: {result.get('password', 'N/A')}")

        elif name == "lock_database":
            _get_client().lock_database()
            return _tool_result("Database locked.")

        elif name == "get_database_groups":
            result = _get_client().get_database_groups()

            def fmt(g: dict, depth: int = 0) -> str:
                indent = "  " * depth
                s = f"{indent}- {g.get('name', '?')} ({g.get('uuid', '?')})"
                for child in g.get("children", []):
                    s += "\n" + fmt(child, depth + 1)
                return s

            groups = result.get("groups", [])
            tree = ("\n".join(fmt(g) for g in groups)
                    if groups else "No groups")
            default = result.get("defaultGroup", "N/A")
            return _tool_result(
                f"Default group: {default}\n\n{tree}")

        elif name == "get_database_hash":
            result = _get_client().get_databasehash()
            return _tool_result(
                f"Database hash: {result.get('hash', 'N/A')}\n"
                f"KeePassXC version: {result.get('version', 'N/A')}")

        elif name == "associate":
            assoc_id = _get_client().associate()
            return _tool_result(
                f'Successfully associated with database as "{assoc_id}".')

        else:
            return _tool_error(f"Unknown tool: {name}")

    except Exception as e:
        log(f'Error in tool "{name}": {e}')
        return _tool_error(f"Error: {e}")


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

def _handle(msg: dict) -> dict | None:
    """Process one JSON-RPC message. Returns response or None for notifications."""
    method = msg.get("method")
    msg_id = msg.get("id")
    params = msg.get("params", {})

    if method == "initialize":
        return _result(msg_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "keepassxc-mcp", "version": "1.0.0"},
        })

    elif method == "tools/list":
        return _result(msg_id, {"tools": TOOLS})

    elif method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})
        return _result(msg_id, _dispatch_tool(tool_name, tool_args))

    elif method == "ping":
        return _result(msg_id, {})

    elif msg_id is not None:
        return _error(msg_id, -32601, f"Method not found: {method}")

    # Notifications (no id) — ignore silently
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    log("KeePassXC MCP server starting")
    while True:
        msg = _read_message()
        if msg is None:
            break
        resp = _handle(msg)
        if resp is not None:
            _write_message(resp)
