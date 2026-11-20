// Zero-dependency relay server (Node http).
//
// It is deliberately "dumb": it authenticates nobody, parses no ciphertext,
// and enforces no membership. All access control happens cryptographically on
// clients via epoch-secret envelopes. The server only:
//
//   - appends opaque event blobs to per-group logs
//   - serves the log back
//   - fans out new events over Server-Sent Events
//
// Endpoints:
//   GET  /api/groups                       list group ids
//   POST /api/groups/:groupId/events       append an opaque event
//   GET  /api/groups/:groupId/events       read the log (?after=N)
//   GET  /api/groups/:groupId/stream       SSE live feed
//   GET  /api/dump                         full server dump (for the attacker tool)
//   GET  /*                                static demo page assets

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { RelayStore } from "./store.js";
import type { GroupEvent } from "../client/crypto/protocol.js";

const PORT = Number(process.env.PORT ?? 8787);
const DATA_FILE = process.env.DATA_FILE ?? "data/store.json";
const PUBLIC_DIR = join(process.cwd(), "dist", "public");

interface SseClient {
  groupId: string;
  res: ServerResponse;
}

const store = new RelayStore(DATA_FILE);
const sseClients = new Set<SseClient>();

function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(payload);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > 5 * 1024 * 1024) reject(new Error("body too large"));
      else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

async function handleApi(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
  const path = url.pathname;

  if (req.method === "GET" && path === "/api/groups") {
    return json(res, 200, { groups: store.listGroups() });
  }

  if (req.method === "GET" && path === "/api/dump") {
    return json(res, 200, { events: store.dump() });
  }

  const groupMatch = path.match(/^\/api\/groups\/([A-Za-z0-9_-]+)\/(events|stream)\/?$/);
  if (!groupMatch) return json(res, 404, { error: "unknown endpoint" });
  const groupId = groupMatch[1]!;
  const resource = groupMatch[2]!;

  if (resource === "stream" && req.method === "GET") {
    res.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
    });
    const client: SseClient = { groupId, res };
    sseClients.add(client);
    res.write(`event: ready\ndata: {"groupId":${JSON.stringify(groupId)}}\n\n`);
    req.on("close", () => sseClients.delete(client));
    return;
  }

  if (resource === "events" && req.method === "GET") {
    const after = Number(url.searchParams.get("after") ?? 0);
    return json(res, 200, { events: store.events(groupId, Number.isFinite(after) ? after : 0) });
  }

  if (resource === "events" && req.method === "POST") {
    let parsed: { event?: GroupEvent };
    try {
      parsed = JSON.parse(await readBody(req)) as { event?: GroupEvent };
    } catch {
      return json(res, 400, { error: "invalid JSON" });
    }
    const event = parsed.event;
    if (!event || (event.kind !== "commit" && event.kind !== "message")) {
      return json(res, 400, { error: "expected {event: GroupCommit|GroupMessage}" });
    }
    if (event.groupId !== groupId) {
      return json(res, 400, { error: "event groupId does not match URL" });
    }
    // The relay does NOT verify signatures, parse members, or inspect ciphertext.
    const stored = store.append(groupId, event);
    for (const c of sseClients) {
      if (c.groupId === groupId) c.res.write(`event: event\ndata: ${JSON.stringify(stored)}\n\n`);
    }
    return json(res, 201, { stored });
  }

  return json(res, 405, { error: "method not allowed" });
}

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
};

async function serveStatic(res: ServerResponse, urlPath: string): Promise<void> {
  const rel = normalize(urlPath === "/" ? "index.html" : urlPath.replace(/^\/+/, ""));
  if (rel.startsWith("..")) {
    res.writeHead(400).end("bad path");
    return;
  }
  const file = join(PUBLIC_DIR, rel);
  try {
    const content = await readFile(file);
    res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream" });
    res.end(content);
  } catch {
    // SPA fallback only for extensionless routes; asset-like paths 404 loudly
    if (extname(rel)) {
      res.writeHead(404, { "content-type": "text/plain" }).end("asset not found");
      return;
    }
    try {
      const index = await readFile(join(PUBLIC_DIR, "index.html"));
      res.writeHead(200, { "content-type": MIME[".html"]! });
      res.end(index);
    } catch {
      res.writeHead(404, { "content-type": "text/plain" }).end("not found");
    }
  }
}

const server = createServer((req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  if (url.pathname.startsWith("/api/")) {
    handleApi(req, res, url).catch((err) => json(res, 500, { error: (err as Error).message }));
  } else {
    serveStatic(res, url.pathname).catch(() => res.writeHead(500).end("server error"));
  }
});

server.listen(PORT, () => {
  console.log(`E2EE relay server listening on http://localhost:${PORT}`);
  console.log(`Storage: ${DATA_FILE} (${store.allEvents().length} existing events)`);
});
