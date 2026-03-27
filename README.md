# keepassxc-mcp

MCP (Model Context Protocol) server for [KeePassXC](https://keepassxc.org/) password manager. Uses the same browser integration protocol as the KeePassXC Firefox/Chrome extension — communicating over the `keepassxc-proxy` Unix domain socket with TweetNaCl box encryption.

## Features

- **get_logins** — Look up credentials by URL
- **get_totp** — Retrieve TOTP codes for entries
- **set_login** — Save or update credentials
- **generate_password** — Generate a password via KeePassXC's generator
- **lock_database** — Lock the database remotely
- **get_database_groups** — List the group/folder tree
- **get_database_hash** — Get database hash (detect changes)
- **associate** — Manually (re-)associate with the database

## Prerequisites

1. **KeePassXC** running with **Browser Integration** enabled:
   - Settings → Browser Integration → Enable browser integration
   - The database must be unlocked for most operations
2. **Node.js** ≥ 18

## Setup

### Local (KeePassXC on same machine)

```bash
cd keepassxc-mcp
npm install && npm run build
```

The server auto-detects the socket path:
- **Linux:** `$XDG_RUNTIME_DIR/kpxc_server` or `/run/user/<uid>/kpxc_server`
- **macOS:** `$TMPDIR/kpxc_server` or `/tmp/kpxc_server`

### Remote (KeePassXC on a different machine)

When KeePassXC runs on a host and the MCP server runs in a VM/container, forward the socket over TCP.

**On the host** (where KeePassXC runs):

macOS:
```bash
socat TCP-LISTEN:19455,reuseaddr,fork UNIX-CONNECT:${TMPDIR}kpxc_server
```

Linux:
```bash
socat TCP-LISTEN:19455,reuseaddr,fork UNIX-CONNECT:${XDG_RUNTIME_DIR}/kpxc_server
```

Windows (PowerShell, requires socat via WSL or nmap's ncat):
```powershell
# From WSL:
socat TCP-LISTEN:19455,reuseaddr,fork UNIX-CONNECT:/mnt/wslg/runtime-dir/kpxc_server
```

Then configure the MCP server to connect via TCP (see environment variables below).

## Windsurf Configuration

Add to `~/.codeium/windsurf/mcp_config.json`:

### Local socket
```json
{
  "mcpServers": {
    "keepassxc": {
      "command": "node",
      "args": ["/path/to/keepassxc-mcp/dist/index.js"],
      "env": {}
    }
  }
}
```

### Remote via TCP
```json
{
  "mcpServers": {
    "keepassxc": {
      "command": "node",
      "args": ["/path/to/keepassxc-mcp/dist/index.js"],
      "env": {
        "KEEPASSXC_HOST": "192.168.0.1",
        "KEEPASSXC_PORT": "19455"
      }
    }
  }
}
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `KEEPASSXC_HOST` | *(unset)* | TCP host (enables TCP mode instead of Unix socket) |
| `KEEPASSXC_PORT` | *(unset)* | TCP port |
| `KEEPASSXC_SOCKET` | auto-detected | Unix domain socket path |
| `KEEPASSXC_IDENTITY` | `~/.local/share/keepassxc-mcp/identity.json` | Path to persistent association identity |
| `KEEPASSXC_TIMEOUT` | `30000` | Response timeout in milliseconds |

## First Use

On the first tool call, the server will:
1. Connect to KeePassXC (socket or TCP)
2. Exchange ephemeral session keys
3. Request association — **a dialog will appear in KeePassXC asking you to confirm**
4. Store the association identity for future sessions

Subsequent connections reuse the stored identity (validated via `test-associate`).

## Security Notes

- All messages (except the initial key exchange) are encrypted with **NaCl box** (X25519 + XSalsa20-Poly1305)
- The identity file at `~/.local/share/keepassxc-mcp/identity.json` is created with mode `0600`
- Session keys are ephemeral — regenerated on every connection
- The identity key is equivalent to what the browser extension stores; protect it accordingly
- If using TCP forwarding, the NaCl encryption protects the payload, but consider using SSH tunneling for defense in depth

## Protocol Reference

This server implements the [keepassxc-browser protocol](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md).
