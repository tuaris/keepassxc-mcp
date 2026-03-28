#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn, ChildProcess } from "node:child_process";
import * as readline from "node:readline";
import path from "node:path";

// ---------------------------------------------------------------------------
// Logging (stderr only — stdout is reserved for MCP JSON-RPC)
// ---------------------------------------------------------------------------
function log(msg: string): void {
  process.stderr.write(`[keepassxc-mcp] ${msg}\n`);
}

// ---------------------------------------------------------------------------
// KeePassXC protocol client — thin wrapper around kpxc-client.py
//
// All TCP, encryption, identity, and protocol logic lives in the Python
// subprocess.  This class just sends JSON commands and reads JSON responses.
// ---------------------------------------------------------------------------
class KeePassXCClient {
  private proc: ChildProcess | null = null;
  private rl: readline.Interface | null = null;
  private pending: {
    resolve: (v: any) => void;
    reject: (e: Error) => void;
  } | null = null;

  private ensureProc(): void {
    if (this.proc && !this.proc.killed) return;
    const script = path.join(
      path.dirname(new URL(import.meta.url).pathname),
      "kpxc-client.py",
    );
    this.proc = spawn("python3", ["-u", script], {
      stdio: ["pipe", "pipe", "pipe"],
      env: process.env,
    });
    this.proc.stderr!.on("data", (chunk: Buffer) => {
      // Forward Python client logs to our stderr
      for (const line of chunk.toString().split("\n")) {
        if (line.trim()) process.stderr.write(`${line}\n`);
      }
    });
    this.proc.on("close", (code) => {
      log(`kpxc-client exited with code ${code}`);
      if (this.pending) {
        this.pending.reject(new Error("kpxc-client process exited"));
        this.pending = null;
      }
      this.proc = null;
      this.rl = null;
    });
    this.rl = readline.createInterface({ input: this.proc.stdout! });
    this.rl.on("line", (line: string) => {
      if (!this.pending) return;
      try {
        const data = JSON.parse(line);
        const p = this.pending;
        this.pending = null;
        if (data.ok) {
          p.resolve(data);
        } else {
          p.reject(new Error(data.error || "Unknown error from kpxc-client"));
        }
      } catch {
        // Incomplete or invalid — ignore
      }
    });
    log("kpxc-client subprocess started");
  }

  private send(cmd: object): Promise<any> {
    return new Promise((resolve, reject) => {
      this.ensureProc();
      if (this.pending) {
        return reject(new Error("Another request is already in flight"));
      }
      this.pending = { resolve, reject };
      const line = JSON.stringify(cmd) + "\n";
      this.proc!.stdin!.write(line);
    });
  }

  disconnect(): void {
    if (this.proc && !this.proc.killed) {
      this.proc.stdin!.end();
      this.proc.kill();
    }
    this.proc = null;
    this.rl = null;
    this.pending = null;
  }

  // ---- Public API (each maps to an MCP tool) --------------------------------

  async getLogins(url: string, submitUrl?: string): Promise<any> {
    const r = await this.send({ cmd: "get-logins", url, submitUrl });
    return r.response;
  }

  async getTotp(uuid: string): Promise<any> {
    const r = await this.send({ cmd: "get-totp", uuid });
    return r.response;
  }

  async setLogin(params: {
    url: string;
    login: string;
    password: string;
    submitUrl?: string;
    group?: string;
    groupUuid?: string;
    uuid?: string;
  }): Promise<any> {
    const r = await this.send({ cmd: "set-login", params });
    return r.response;
  }

  async generatePassword(): Promise<any> {
    const r = await this.send({ cmd: "generate-password" });
    return r.response;
  }

  async lockDatabase(): Promise<any> {
    const r = await this.send({ cmd: "lock-database" });
    return r.response;
  }

  async getDatabaseGroups(): Promise<any> {
    const r = await this.send({ cmd: "get-database-groups" });
    return r.response;
  }

  async getDatabaseHash(): Promise<any> {
    const r = await this.send({ cmd: "get-databasehash" });
    return r.response;
  }

  async associate(): Promise<string> {
    const r = await this.send({ cmd: "associate" });
    return r.id;
  }
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------
const client = new KeePassXCClient();

const server = new Server(
  { name: "keepassxc-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

// ---- Tool catalogue ---------------------------------------------------------

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_logins",
      description:
        "Retrieve saved credentials (username + password) from KeePassXC for a given URL. " +
        "Returns all matching entries including login, password, name, and UUID.",
      inputSchema: {
        type: "object" as const,
        properties: {
          url: {
            type: "string",
            description: "URL to look up credentials for (e.g. https://example.com)",
          },
          submitUrl: {
            type: "string",
            description: "Optional form submit URL for more specific matching",
          },
        },
        required: ["url"],
      },
    },
    {
      name: "get_totp",
      description:
        "Get the current TOTP (time-based one-time password) code for a KeePassXC entry. " +
        "Requires the entry UUID (obtain via get_logins first).",
      inputSchema: {
        type: "object" as const,
        properties: {
          uuid: {
            type: "string",
            description: "UUID of the KeePassXC entry",
          },
        },
        required: ["uuid"],
      },
    },
    {
      name: "set_login",
      description:
        "Save or update credentials in KeePassXC. " +
        "To update an existing entry, provide its uuid.",
      inputSchema: {
        type: "object" as const,
        properties: {
          url: { type: "string", description: "URL for the credential" },
          login: { type: "string", description: "Username / login" },
          password: { type: "string", description: "Password" },
          submitUrl: { type: "string", description: "Form submit URL" },
          group: { type: "string", description: "Target group name" },
          groupUuid: { type: "string", description: "Target group UUID" },
          uuid: {
            type: "string",
            description: "Entry UUID (for updating an existing entry)",
          },
        },
        required: ["url", "login", "password"],
      },
    },
    {
      name: "generate_password",
      description:
        "Generate a random password using KeePassXC's password generator. " +
        "Note: this may open the KeePassXC password generator dialog on the host " +
        "and wait for the user to confirm.",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
    {
      name: "lock_database",
      description: "Lock the currently open KeePassXC database.",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
    {
      name: "get_database_groups",
      description:
        "List all groups (folders) in the KeePassXC database as a tree.",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
    {
      name: "get_database_hash",
      description:
        "Get the SHA-256 hash of the current KeePassXC database. " +
        "Useful for detecting if the database has changed.",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
    {
      name: "associate",
      description:
        "Manually (re-)associate this MCP server with the KeePassXC database. " +
        "A confirmation dialog will appear in KeePassXC. " +
        "Usually not needed — association happens automatically on first use.",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
  ],
}));

// ---- Tool dispatch ----------------------------------------------------------

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      // -- get_logins --
      case "get_logins": {
        const result = await client.getLogins(
          args?.url as string,
          args?.submitUrl as string | undefined,
        );
        const entries: any[] = result.entries || [];
        if (entries.length === 0) {
          return {
            content: [
              { type: "text", text: "No credentials found for this URL." },
            ],
          };
        }
        const lines = entries.map(
          (e: any, i: number) =>
            `Entry ${i + 1}:\n` +
            `  Name: ${e.name}\n` +
            `  Login: ${e.login}\n` +
            `  Password: ${e.password}\n` +
            `  UUID: ${e.uuid || "N/A"}` +
            (e.expired === "true" ? "\n  WARNING: expired" : "") +
            (e.totp ? `\n  TOTP: ${e.totp}` : "") +
            (e.stringFields?.length
              ? "\n  Custom fields: " +
                e.stringFields
                  .map((f: any) => {
                    const k = Object.keys(f)[0];
                    return `${k}=${f[k]}`;
                  })
                  .join(", ")
              : ""),
        );
        return {
          content: [
            {
              type: "text",
              text: `Found ${entries.length} credential(s):\n\n${lines.join("\n\n")}`,
            },
          ],
        };
      }

      // -- get_totp --
      case "get_totp": {
        const result = await client.getTotp(args?.uuid as string);
        return {
          content: [{ type: "text", text: `TOTP: ${result.totp}` }],
        };
      }

      // -- set_login --
      case "set_login": {
        const result = await client.setLogin({
          url: args?.url as string,
          login: args?.login as string,
          password: args?.password as string,
          submitUrl: args?.submitUrl as string | undefined,
          group: args?.group as string | undefined,
          groupUuid: args?.groupUuid as string | undefined,
          uuid: args?.uuid as string | undefined,
        });
        return {
          content: [
            {
              type: "text",
              text:
                result.success === "true"
                  ? "Credentials saved successfully."
                  : `Result: ${JSON.stringify(result)}`,
            },
          ],
        };
      }

      // -- generate_password --
      case "generate_password": {
        const result = await client.generatePassword();
        return {
          content: [
            {
              type: "text",
              text: `Generated password: ${result.password}`,
            },
          ],
        };
      }

      // -- lock_database --
      case "lock_database": {
        await client.lockDatabase();
        return {
          content: [{ type: "text", text: "Database locked." }],
        };
      }

      // -- get_database_groups --
      case "get_database_groups": {
        const result = await client.getDatabaseGroups();
        const fmt = (g: any, depth = 0): string => {
          const indent = "  ".repeat(depth);
          let s = `${indent}- ${g.name} (${g.uuid})`;
          if (g.children?.length) {
            s +=
              "\n" +
              g.children.map((c: any) => fmt(c, depth + 1)).join("\n");
          }
          return s;
        };
        const tree =
          result.groups?.map((g: any) => fmt(g)).join("\n") || "No groups";
        return {
          content: [
            {
              type: "text",
              text:
                `Default group: ${result.defaultGroup || "N/A"}\n\n${tree}`,
            },
          ],
        };
      }

      // -- get_database_hash --
      case "get_database_hash": {
        const result = await client.getDatabaseHash();
        return {
          content: [
            {
              type: "text",
              text: `Database hash: ${result.hash}\nKeePassXC version: ${result.version}`,
            },
          ],
        };
      }

      // -- associate --
      case "associate": {
        const id = await client.associate();
        return {
          content: [
            {
              type: "text",
              text: `Successfully associated with database as "${id}".`,
            },
          ],
        };
      }

      default:
        return {
          content: [{ type: "text", text: `Unknown tool: ${name}` }],
          isError: true,
        };
    }
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    log(`Error in tool "${name}": ${msg}`);
    return {
      content: [{ type: "text", text: `Error: ${msg}` }],
      isError: true,
    };
  }
});

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);

  log("KeePassXC MCP server running");
  const host = process.env.KEEPASSXC_HOST || "127.0.0.1";
  const port = process.env.KEEPASSXC_PORT || "19455";
  log(`Target: TCP ${host}:${port}`);
}

main().catch((err) => {
  log(`Fatal: ${err instanceof Error ? err.message : err}`);
  process.exit(1);
});
