import express, { type Request, type Response } from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { createContextMiddleware } from "@ctxprotocol/sdk";

import { TOOLS } from "./tools.js";
import { getDomainIntelligence, getSubdomainsDirectly, normalizeDomain, getCacheSize } from "./fetcher.js";
import { ENV } from "./env.js";

// ── Logger ─────────────────────────────────────────────────────────────────

const log = {
  info:  (msg: string, meta?: object) => console.log( `[INFO]  ${msg}`, meta ? JSON.stringify(meta) : ""),
  warn:  (msg: string, meta?: object) => console.warn( `[WARN]  ${msg}`, meta ? JSON.stringify(meta) : ""),
  error: (msg: string, meta?: object) => console.error(`[ERROR] ${msg}`, meta ? JSON.stringify(meta) : ""),
};

// ── Tool handler ───────────────────────────────────────────────────────────

async function handleTool(name: string, args: Record<string, unknown>) {
  const domain = normalizeDomain((args.domain ?? "") as string);

  // get_subdomains has its own dedicated fetch path with a 20s timeout
  // and the full historical crt.sh corpus. Route it before the full intel fetch.
  if (name === "get_subdomains") {
    return await getSubdomainsDirectly(domain);
  }

  // The other three tools share the getDomainIntelligence cache.
  // First call pays the cold fetch penalty; subsequent calls are cache reads.
  const intel = await getDomainIntelligence(domain);

  switch (name) {
    case "get_domain_intelligence":
      return intel;

    case "get_tech_stack":
      return {
        domain:         intel.domain,
        tech_stack:     intel.tech_stack,
        data_freshness: intel.data_freshness,
      };

    case "get_dns_records":
      return {
        domain:         intel.domain,
        dns:            intel.dns,
        data_freshness: intel.data_freshness,
      };

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ── MCP Server factory ─────────────────────────────────────────────────────

function makeServer(): Server {
  const server = new Server(
    { name: "domain-intel", version: "1.0.0" },
    { capabilities: { tools: { listChanged: false } } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    log.info("tools/list");
    return { tools: TOOLS };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    const t0 = Date.now();
    log.info("tool/call", { name, domain: args.domain });

    try {
      const result = await handleTool(name, args as Record<string, unknown>);
      log.info("tool/ok", { name, ms: Date.now() - t0 });
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        structuredContent: result,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      log.error("tool/err", { name, ms: Date.now() - t0, message });
      return {
        content: [{ type: "text", text: `Error: ${message}` }],
        isError: true,
        structuredContent: { error: message },
      };
    }
  });

  return server;
}

// ── Express app ────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());

app.use((req, _res, next) => {
  log.info("request", { method: req.method, path: req.path, body_method: req.body?.method });
  next();
});

// Context Protocol middleware — guards tools/call with JWT verification
app.use("/mcp", createContextMiddleware());

// ── SSE sessions ───────────────────────────────────────────────────────────

const sessions = new Map<string, SSEServerTransport>();

app.get("/mcp", async (_req: Request, res: Response) => {
  const transport = new SSEServerTransport("/mcp", res);
  const server    = makeServer();
  sessions.set(transport.sessionId, transport);

  res.on("close", () => {
    sessions.delete(transport.sessionId);
    log.info("sse/close", { activeSessions: sessions.size });
  });

  await server.connect(transport);
});

// ── Stateless POST handler ─────────────────────────────────────────────────

app.post("/mcp", async (req: Request, res: Response) => {
  const sessionId = req.query.sessionId as string | undefined;

  // SSE session POST
  if (sessionId) {
    const transport = sessions.get(sessionId);
    if (!transport) { res.status(404).json({ error: "Session not found" }); return; }
    await transport.handlePostMessage(req, res, req.body);
    return;
  }

  const { method, id } = req.body ?? {};

  if (method === "initialize") {
    res.json({
      jsonrpc: "2.0", id,
      result: {
        protocolVersion: "2024-11-05",
        serverInfo: { name: "domain-intel", version: "1.0.0" },
        capabilities: { tools: { listChanged: false } },
      },
    });
    return;
  }

  if (method === "notifications/initialized") {
    log.info("notifications/initialized");
    res.status(204).end();
    return;
  }

  if (method === "notifications/cancelled") {
    log.warn("tool/cancelled", { id });
    res.json({ jsonrpc: "2.0", id, result: {} });
    return;
  }

  if (method === "tools/list") {
    log.info("tools/list");
    res.json({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
    return;
  }

  if (method === "tools/call") {
    const { name, arguments: args = {} } = req.body?.params ?? {};
    const t0 = Date.now();
    log.info("tool/call", { name, domain: args.domain });

    try {
      const result = await handleTool(name as string, args as Record<string, unknown>);
      log.info("tool/ok", { name, ms: Date.now() - t0 });
      res.json({
        jsonrpc: "2.0", id,
        result: {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          structuredContent: result,
        },
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      log.error("tool/err", { name, ms: Date.now() - t0, message });
      res.json({
        jsonrpc: "2.0", id,
        result: {
          content: [{ type: "text", text: `Error: ${message}` }],
          isError: true,
          structuredContent: { error: message },
        },
      });
    }
    return;
  }

  log.warn("unknown_method", { method });
  res.status(400).json({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } });
});

// ── Health ─────────────────────────────────────────────────────────────────

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "domain-intel-mcp",
    version: "1.0.0",
    activeSessions: sessions.size,
    cachedDomains: getCacheSize(),
  });
});

// ── Start ──────────────────────────────────────────────────────────────────

app.listen(ENV.PORT, () => {
  log.info("listening", { port: ENV.PORT, env: ENV.NODE_ENV });
});
