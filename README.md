# KeePassXC MCP Server

MCP (Model Context Protocol) server for [KeePassXC](https://keepassxc.org/) password manager. Uses the same browser integration protocol as the KeePassXC Firefox/Chrome extension — communicating over Unix domain sockets or TCP with NaCl box encryption.

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
2. **Python** ≥ 3.10

## Setup

### Install

```bash
cd keepassxc-mcp
pip install .
```

Or for development:
```bash
pip install -e .
```

### Local (KeePassXC on same machine)

The server auto-detects the Unix socket path:
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

Windows (native bridge — no dependencies):

A native C bridge is included in `bridge/kpxc-bridge.c`. It runs as a **system tray application**,
forwarding TCP connections to the KeePassXC named pipe
(`\\.\pipe\org.keepassxc.KeePassXC.BrowserServer`).

**Install via the Windows installer** (recommended):

Download `kpxc-bridge-VERSION-setup.exe` from
[Releases](https://pacyworld.dev/daniel/keepassxc-mcp/releases). The installer:
- Installs the bridge to `Program Files\KeePassXC Bridge`
- Adds a Start Menu shortcut
- Registers the bridge to start on login (HKCU Run key)
- Creates a Windows Firewall rule for the configured TCP port
- Starts the tray app immediately

**Or run the standalone binary:**

Download `kpxc-bridge.exe` from [Releases](https://pacyworld.dev/daniel/keepassxc-mcp/releases).

```cmd
kpxc-bridge.exe                     Run as tray app (default)
kpxc-bridge.exe -console            Run in console mode (Ctrl+C to stop)
kpxc-bridge.exe -port 19455         Set TCP listen port (default: 19455)
kpxc-bridge.exe -bind 192.168.0.1   Bind to specific interface
kpxc-bridge.exe install             Add to user startup (login)
kpxc-bridge.exe uninstall           Remove from user startup
```

The tray icon indicates connection status (idle vs active) and logs to
`kpxc-bridge.log` next to the executable.

**Build from source** (cross-compile from any OS with [Zig](https://ziglang.org/)):
```bash
zig cc -O2 -target x86_64-windows-gnu bridge/kpxc-bridge.c bridge/resources/kpxc-bridge.rc \
  -lws2_32 -ladvapi32 -lshell32 -luser32 -Wl,--subsystem,windows -o kpxc-bridge.exe
```

Then configure the MCP server to connect via TCP (see environment variables below).

## Windsurf Configuration

Add to `~/.codeium/windsurf/mcp_config.json`:

### Local socket
```json
{
  "mcpServers": {
    "keepassxc": {
      "command": "keepassxc-mcp",
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
      "command": "keepassxc-mcp",
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

## Donations

If you find this project useful, consider a small donation:

| Currency | Address |
|---|---|
| **BTC** | `1B6eyXVRPxdEitW5vWrUnzzXUy6o38P9wN` |
| **LTC** | `MCrnhTAHA3n6X8jUJQj9hed5CT585sJExQ` |
| **PEPE (Ᵽ)** | `Pk3WZshXxi656RNNoVuZTCERVhhv4pyPJS` |
| **DOGE** | `DQgDGexy5tJ4StbMdyGwgfyxhcAGTRrPVB` |

## Protocol Reference

This server implements the [keepassxc-browser protocol](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md).

## License

BSD 2-Clause. See [LICENSE](LICENSE).
