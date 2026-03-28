#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, } from "@modelcontextprotocol/sdk/types.js";
import nacl from "tweetnacl";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
// ---------------------------------------------------------------------------
// Logging (stderr only — stdout is reserved for MCP JSON-RPC)
// ---------------------------------------------------------------------------
function log(msg) {
    process.stderr.write(`[keepassxc-mcp] ${msg}\n`);
}
// ---------------------------------------------------------------------------
// Base64 helpers (avoid extra dependency on tweetnacl-util)
// ---------------------------------------------------------------------------
function toBase64(data) {
    return Buffer.from(data).toString("base64");
}
function fromBase64(str) {
    return new Uint8Array(Buffer.from(str, "base64"));
}
// ---------------------------------------------------------------------------
// Configuration — all via environment variables
// ---------------------------------------------------------------------------
function getDefaultSocketPath() {
    const xdg = process.env.XDG_RUNTIME_DIR;
    if (xdg)
        return path.join(xdg, "kpxc_server");
    if (process.platform === "darwin") {
        return path.join(process.env.TMPDIR || "/tmp", "kpxc_server");
    }
    const uid = process.getuid?.() ?? 1000;
    return `/run/user/${uid}/kpxc_server`;
}
const SOCKET_PATH = process.env.KEEPASSXC_SOCKET || getDefaultSocketPath();
const TCP_HOST = process.env.KEEPASSXC_HOST;
const TCP_PORT = process.env.KEEPASSXC_PORT
    ? parseInt(process.env.KEEPASSXC_PORT, 10)
    : undefined;
const IDENTITY_FILE = process.env.KEEPASSXC_IDENTITY ||
    path.join(os.homedir(), ".local", "share", "keepassxc-mcp", "identity.json");
const RESPONSE_TIMEOUT = parseInt(process.env.KEEPASSXC_TIMEOUT || "30000", 10);
function loadIdentity() {
    try {
        if (fs.existsSync(IDENTITY_FILE)) {
            const data = JSON.parse(fs.readFileSync(IDENTITY_FILE, "utf-8"));
            if (data.id && data.idKey && data.secretKey)
                return data;
        }
    }
    catch {
        log("Warning: failed to load identity file");
    }
    return null;
}
function saveIdentity(identity) {
    const dir = path.dirname(IDENTITY_FILE);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(IDENTITY_FILE, JSON.stringify(identity, null, 2), {
        mode: 0o600,
    });
    log(`Identity saved to ${IDENTITY_FILE}`);
}
// ---------------------------------------------------------------------------
// KeePassXC protocol client
//
// Implements the keepassxc-browser protocol over a Unix domain socket or TCP.
// Encryption uses TweetNaCl box (X25519 + XSalsa20-Poly1305), matching the
// browser extension's use of TweetNaCl.js.
//
// Three key pairs are involved:
//   1. Session key pair (ephemeral, per-connection)
//   2. Server/host key pair (ephemeral, per-connection, from KeePassXC)
//   3. Identification key pair (persistent, stored in identity file)
// ---------------------------------------------------------------------------
class KeePassXCClient {
    socket = null;
    sessionKeyPair;
    serverPublicKey = null;
    clientID;
    identity = null;
    connected = false;
    // Response buffering (socket is stream-oriented)
    buffer = "";
    pendingResolve = null;
    pendingReject = null;
    pendingTimer = null;
    constructor() {
        this.newSession();
        this.identity = loadIdentity();
    }
    /** Generate fresh ephemeral session keys + clientID */
    newSession() {
        this.sessionKeyPair = nacl.box.keyPair();
        this.clientID = toBase64(new Uint8Array(crypto.randomBytes(24)));
        this.serverPublicKey = null;
    }
    // ---- Connection management ------------------------------------------------
    async connect() {
        if (this.connected && this.socket)
            return;
        this.cleanup();
        this.newSession();
        return new Promise((resolve, reject) => {
            const onConnectError = (err) => {
                this.cleanup();
                reject(new Error(`Connection failed: ${err.message}`));
            };
            if (TCP_HOST && TCP_PORT) {
                log(`Connecting to TCP ${TCP_HOST}:${TCP_PORT}`);
                this.socket = net.createConnection({
                    host: TCP_HOST,
                    port: TCP_PORT,
                });
            }
            else {
                log(`Connecting to socket ${SOCKET_PATH}`);
                this.socket = net.createConnection({ path: SOCKET_PATH });
            }
            this.socket.once("error", onConnectError);
            this.socket.on("data", (chunk) => {
                this.buffer += chunk.toString("utf-8");
                this.tryResolve();
            });
            this.socket.on("close", () => {
                log("Socket closed");
                const r = this.pendingReject;
                this.clearPending();
                this.cleanup();
                if (r)
                    r(new Error("Connection closed unexpectedly"));
            });
            this.socket.on("connect", () => {
                this.connected = true;
                // Replace the one-shot error handler with a persistent one
                this.socket.removeListener("error", onConnectError);
                this.socket.on("error", (err) => {
                    log(`Socket error: ${err.message}`);
                    const r = this.pendingReject;
                    this.clearPending();
                    this.cleanup();
                    if (r)
                        r(err);
                });
                log("Connected");
                resolve();
            });
        });
    }
    tryResolve() {
        if (!this.pendingResolve)
            return;
        try {
            const parsed = JSON.parse(this.buffer);
            this.buffer = "";
            const resolve = this.pendingResolve;
            this.clearPending();
            resolve(parsed);
        }
        catch {
            // Incomplete JSON — keep buffering
        }
    }
    clearPending() {
        this.pendingResolve = null;
        this.pendingReject = null;
        if (this.pendingTimer) {
            clearTimeout(this.pendingTimer);
            this.pendingTimer = null;
        }
    }
    cleanup() {
        this.connected = false;
        this.serverPublicKey = null;
        this.clearPending();
        if (this.socket) {
            this.socket.removeAllListeners();
            this.socket.destroy();
            this.socket = null;
        }
    }
    disconnect() {
        this.cleanup();
    }
    // ---- Low-level send/receive -----------------------------------------------
    sendAndReceive(data, timeout) {
        return new Promise((resolve, reject) => {
            if (!this.socket || !this.connected) {
                return reject(new Error("Not connected to KeePassXC"));
            }
            this.pendingResolve = resolve;
            this.pendingReject = reject;
            this.pendingTimer = setTimeout(() => {
                const r = this.pendingReject;
                this.clearPending();
                if (r)
                    r(new Error("Response timeout"));
            }, timeout ?? RESPONSE_TIMEOUT);
            this.socket.write(JSON.stringify(data) + "\n");
        });
    }
    // ---- Encryption / decryption ----------------------------------------------
    encrypt(payload) {
        if (!this.serverPublicKey)
            throw new Error("No server public key — run exchangeKeys first");
        const nonce = new Uint8Array(crypto.randomBytes(24));
        const plaintext = new TextEncoder().encode(JSON.stringify(payload));
        const box = nacl.box(plaintext, nonce, this.serverPublicKey, this.sessionKeyPair.secretKey);
        if (!box)
            throw new Error("NaCl box encryption failed");
        return { message: toBase64(box), nonce: toBase64(nonce) };
    }
    decrypt(messageB64, nonceB64) {
        if (!this.serverPublicKey)
            throw new Error("No server public key");
        const opened = nacl.box.open(fromBase64(messageB64), fromBase64(nonceB64), this.serverPublicKey, this.sessionKeyPair.secretKey);
        if (!opened)
            throw new Error("NaCl box decryption failed (wrong keys?)");
        return JSON.parse(new TextDecoder().decode(opened));
    }
    // ---- Protocol actions -----------------------------------------------------
    /** Step 1: Exchange ephemeral public keys (plaintext) */
    async exchangeKeys() {
        await this.connect();
        const nonce = toBase64(new Uint8Array(crypto.randomBytes(24)));
        const resp = await this.sendAndReceive({
            action: "change-public-keys",
            publicKey: toBase64(this.sessionKeyPair.publicKey),
            nonce,
            clientID: this.clientID,
        });
        if (resp.success !== "true") {
            throw new Error(`Key exchange failed: ${JSON.stringify(resp)}`);
        }
        this.serverPublicKey = fromBase64(resp.publicKey);
        log("Key exchange complete");
    }
    /** Send an encrypted action and return the decrypted response */
    async sendEncrypted(action, payload = {}) {
        if (!this.serverPublicKey)
            await this.exchangeKeys();
        const { message, nonce } = this.encrypt({ action, ...payload });
        const resp = await this.sendAndReceive({
            action,
            message,
            nonce,
            clientID: this.clientID,
        });
        // Unencrypted error
        if (resp.error && !resp.message) {
            throw new Error(`KeePassXC error: ${resp.error} (code: ${resp.errorCode ?? "?"})`);
        }
        // Encrypted response
        if (resp.message && resp.nonce) {
            return this.decrypt(resp.message, resp.nonce);
        }
        return resp;
    }
    /** Wrapped sendEncrypted that retries once on connection failure */
    async request(action, payload = {}) {
        try {
            return await this.sendEncrypted(action, payload);
        }
        catch (err) {
            if (err?.message?.includes("Not connected") ||
                err?.message?.includes("Connection") ||
                err?.message?.includes("closed")) {
                log("Connection lost — reconnecting…");
                this.cleanup();
                return await this.sendEncrypted(action, payload);
            }
            throw err;
        }
    }
    // ---- Association ----------------------------------------------------------
    async associate() {
        if (!this.serverPublicKey)
            await this.exchangeKeys();
        const idKeyPair = nacl.box.keyPair();
        const result = await this.sendEncrypted("associate", {
            key: toBase64(this.sessionKeyPair.publicKey),
            idKey: toBase64(idKeyPair.publicKey),
        });
        if (result.success !== "true") {
            throw new Error(`Association failed: ${JSON.stringify(result)}`);
        }
        const identity = {
            id: result.id,
            idKey: toBase64(idKeyPair.publicKey),
            secretKey: toBase64(idKeyPair.secretKey),
        };
        saveIdentity(identity);
        this.identity = identity;
        log(`Associated as "${result.id}"`);
        return result.id;
    }
    async testAssociate() {
        if (!this.identity)
            return false;
        try {
            const result = await this.sendEncrypted("test-associate", {
                id: this.identity.id,
                key: this.identity.idKey,
            });
            return result.success === "true";
        }
        catch {
            return false;
        }
    }
    /** Ensure we have an active, validated association */
    async ensureAssociated() {
        if (!this.serverPublicKey)
            await this.exchangeKeys();
        if (this.identity) {
            if (await this.testAssociate()) {
                log(`Association "${this.identity.id}" valid`);
                return;
            }
            log("Stored association invalid — re-associating");
        }
        await this.associate();
    }
    /** Like ensureAssociated but with automatic reconnect on stale socket */
    async ensureReady() {
        try {
            await this.ensureAssociated();
        }
        catch (err) {
            if (err?.message?.includes("Not connected") ||
                err?.message?.includes("Connection") ||
                err?.message?.includes("closed")) {
                log("Connection lost during readiness check — reconnecting…");
                this.cleanup();
                await this.ensureAssociated();
                return;
            }
            throw err;
        }
    }
    // ---- Public API (each maps to an MCP tool) --------------------------------
    async getLogins(url, submitUrl) {
        await this.ensureReady();
        const payload = {
            url,
            keys: [{ id: this.identity.id, key: this.identity.idKey }],
        };
        if (submitUrl)
            payload.submitUrl = submitUrl;
        return this.request("get-logins", payload);
    }
    async getTotp(uuid) {
        await this.ensureReady();
        return this.request("get-totp", { uuid });
    }
    async setLogin(params) {
        await this.ensureReady();
        return this.request("set-login", {
            ...params,
            id: this.identity.id,
        });
    }
    async generatePassword() {
        // generate-password uses a slightly different request format:
        // no encrypted message body, but the response IS encrypted.
        if (!this.serverPublicKey)
            await this.exchangeKeys();
        const nonce = toBase64(new Uint8Array(crypto.randomBytes(24)));
        const requestID = crypto.randomBytes(4).toString("hex");
        const resp = await this.sendAndReceive({
            action: "generate-password",
            nonce,
            clientID: this.clientID,
            requestID,
        }, 60000);
        if (resp.message && resp.nonce) {
            return this.decrypt(resp.message, resp.nonce);
        }
        if (resp.error) {
            throw new Error(`KeePassXC error: ${resp.error} (code: ${resp.errorCode ?? "?"})`);
        }
        return resp;
    }
    async lockDatabase() {
        await this.ensureReady();
        try {
            return await this.request("lock-database");
        }
        catch (err) {
            // lock-database "succeeds" by returning errorCode 1 / "Database not opened"
            if (err?.message?.includes("Database not opened")) {
                return { success: "true", locked: true };
            }
            throw err;
        }
    }
    async getDatabaseGroups() {
        await this.ensureReady();
        return this.request("get-database-groups");
    }
    async getDatabaseHash() {
        await this.ensureReady();
        return this.request("get-databasehash");
    }
}
// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------
const client = new KeePassXCClient();
const server = new Server({ name: "keepassxc-mcp", version: "1.0.0" }, { capabilities: { tools: {} } });
// ---- Tool catalogue ---------------------------------------------------------
server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
        {
            name: "get_logins",
            description: "Retrieve saved credentials (username + password) from KeePassXC for a given URL. " +
                "Returns all matching entries including login, password, name, and UUID.",
            inputSchema: {
                type: "object",
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
            description: "Get the current TOTP (time-based one-time password) code for a KeePassXC entry. " +
                "Requires the entry UUID (obtain via get_logins first).",
            inputSchema: {
                type: "object",
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
            description: "Save or update credentials in KeePassXC. " +
                "To update an existing entry, provide its uuid.",
            inputSchema: {
                type: "object",
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
            description: "Generate a random password using KeePassXC's password generator. " +
                "Note: this may open the KeePassXC password generator dialog on the host " +
                "and wait for the user to confirm.",
            inputSchema: {
                type: "object",
                properties: {},
            },
        },
        {
            name: "lock_database",
            description: "Lock the currently open KeePassXC database.",
            inputSchema: {
                type: "object",
                properties: {},
            },
        },
        {
            name: "get_database_groups",
            description: "List all groups (folders) in the KeePassXC database as a tree.",
            inputSchema: {
                type: "object",
                properties: {},
            },
        },
        {
            name: "get_database_hash",
            description: "Get the SHA-256 hash of the current KeePassXC database. " +
                "Useful for detecting if the database has changed.",
            inputSchema: {
                type: "object",
                properties: {},
            },
        },
        {
            name: "associate",
            description: "Manually (re-)associate this MCP server with the KeePassXC database. " +
                "A confirmation dialog will appear in KeePassXC. " +
                "Usually not needed — association happens automatically on first use.",
            inputSchema: {
                type: "object",
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
                const result = await client.getLogins(args?.url, args?.submitUrl);
                const entries = result.entries || [];
                if (entries.length === 0) {
                    return {
                        content: [
                            { type: "text", text: "No credentials found for this URL." },
                        ],
                    };
                }
                const lines = entries.map((e, i) => `Entry ${i + 1}:\n` +
                    `  Name: ${e.name}\n` +
                    `  Login: ${e.login}\n` +
                    `  Password: ${e.password}\n` +
                    `  UUID: ${e.uuid || "N/A"}` +
                    (e.expired === "true" ? "\n  WARNING: expired" : "") +
                    (e.totp ? `\n  TOTP: ${e.totp}` : "") +
                    (e.stringFields?.length
                        ? "\n  Custom fields: " +
                            e.stringFields
                                .map((f) => {
                                const k = Object.keys(f)[0];
                                return `${k}=${f[k]}`;
                            })
                                .join(", ")
                        : ""));
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
                const result = await client.getTotp(args?.uuid);
                return {
                    content: [{ type: "text", text: `TOTP: ${result.totp}` }],
                };
            }
            // -- set_login --
            case "set_login": {
                const result = await client.setLogin({
                    url: args?.url,
                    login: args?.login,
                    password: args?.password,
                    submitUrl: args?.submitUrl,
                    group: args?.group,
                    groupUuid: args?.groupUuid,
                    uuid: args?.uuid,
                });
                return {
                    content: [
                        {
                            type: "text",
                            text: result.success === "true"
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
                const fmt = (g, depth = 0) => {
                    const indent = "  ".repeat(depth);
                    let s = `${indent}- ${g.name} (${g.uuid})`;
                    if (g.children?.length) {
                        s +=
                            "\n" +
                                g.children.map((c) => fmt(c, depth + 1)).join("\n");
                    }
                    return s;
                };
                const tree = result.groups?.map((g) => fmt(g)).join("\n") || "No groups";
                return {
                    content: [
                        {
                            type: "text",
                            text: `Default group: ${result.defaultGroup || "N/A"}\n\n${tree}`,
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
    }
    catch (error) {
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
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    log("KeePassXC MCP server running");
    if (TCP_HOST && TCP_PORT) {
        log(`Target: TCP ${TCP_HOST}:${TCP_PORT}`);
    }
    else {
        log(`Target: socket ${SOCKET_PATH}`);
    }
    log(`Identity: ${IDENTITY_FILE}`);
}
main().catch((err) => {
    log(`Fatal: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
});
//# sourceMappingURL=index.js.map