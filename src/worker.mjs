import token_html from "./token.html";

// OAuth endpoints and client id are based on the official Qwen Code implementation.
// Source: https://github.com/QwenLM/qwen-code/blob/105ad743faa59f0a8f575f859d3b5869ff00acb9/packages/core/src/qwen/qwenOAuth2.ts
const QWEN_OAUTH_BASE_URL = "https://chat.qwen.ai";
const QWEN_OAUTH_TOKEN_ENDPOINT = `${QWEN_OAUTH_BASE_URL}/api/v1/oauth2/token`;
const QWEN_OAUTH_CLIENT_ID = "f0304373b74a44d2b584a3fb70ca9e56";


// Default resource_url for Qwen OAuth credentials (matches typical ~/.qwen/oauth_creds.json content).
// Note: resource_url is expected to be overridden by the user's actual creds when provided.
const DEFAULT_RESOURCE_URL = "portal.qwen.ai";

// Refresh buffer to avoid racing the real expiry.
const TOKEN_REFRESH_BUFFER_MS = 30_000;

export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (e) {
      // Always return a JSON-ish error for clients.
      return withCORS(
        new Response(JSON.stringify({ error: e?.message || String(e) }), {
          status: 500,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
          },
        }),
      );
    }
  },
};

/**
 * @typedef {Object} QwenCredentialsRecord
 * @property {string} access_token
 * @property {string} refresh_token
 * @property {string} token_type
 * @property {string=} resource_url
 * @property {number} expiry_date
 */

async function route(request, env) {
  if (request.method === "OPTIONS") {
    return handleOPTIONS();
  }

  const url = new URL(request.url);

  // GET /token -> HTML form
  if (url.pathname === "/token" && request.method === "GET") {
    return new Response(token_html, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  }

  // POST /token -> persist, return generated OpenAI-compatible token
  if (url.pathname === "/token" && request.method === "POST") {
    const resp = await handleTokenSubmit(request, env);
    return withCORS(resp);
  }

  // Everything else requires our OpenAI-compatible token
  const authKey = getBearerToken(request);
  if (!authKey) {
    return withCORS(new Response("401 Unauthorized", { status: 401 }));
  }

  const kv = env.KV;
  if (!kv) {
    return withCORS(
      new Response(
        "500 Server Misconfigured: KV binding 'KV' is missing (see wrangler.toml)",
        { status: 500 },
      ),
    );
  }

  const recordKey = `oai:${authKey}`;
  /** @type {QwenCredentialsRecord | null} */
  let creds = await kv.get(recordKey, { type: "json" });
  if (!creds) {
    return withCORS(new Response("401 Unauthorized", { status: 401 }));
  }

  try {
    creds = await ensureFreshCredentials(creds, kv, recordKey);
  } catch (e) {
    return withCORS(
      new Response(JSON.stringify({ error: e?.message || "Unauthorized" }), {
        status: 401,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store",
        },
      }),
    );
  }

  const upstreamBase = normalizeEndpoint(creds.resource_url || DEFAULT_RESOURCE_URL);

  // Compatibility shim: support OpenAI Responses API by converting it to Chat Completions.
  // Only a minimal subset is supported (text + image urls).
  let path = url.pathname;
  let overrideBodyText;
  let mapToResponses = false;

  if (request.method === "POST") {
    const contentType = request.headers.get("Content-Type") || "";
    const isJSON = contentType.includes("application/json");

    if (path === "/v1/responses" || path === "/responses") {
      if (!isJSON) {
        return withCORS(new Response("Unsupported Content-Type for /v1/responses", { status: 415 }));
      }
      const bodyText = await request.text();
      try {
        const bodyJson = JSON.parse(bodyText);
        const { chatBody } = convertResponsesToChatBody(bodyJson);
        overrideBodyText = JSON.stringify(chatBody);
        path = "/chat/completions";
        mapToResponses = true;
      } catch (e) {
        const msg = (e && e.message) ? e.message : "Invalid JSON body for /v1/responses";
        const status = e && e.status ? e.status : 400;
        return withCORS(new Response(msg, { status }));
      }
    }
  }

  // Keep OpenAI-ish path style: allow both /v1/* and /*.
  let upstreamPath = path;
  if (upstreamPath.startsWith("/v1/")) {
    upstreamPath = upstreamPath.substring(3);
  }

  const upstreamUrl = new URL(upstreamBase + upstreamPath);
  upstreamUrl.search = url.search;

  const upstreamHeaders = new Headers(request.headers);
  upstreamHeaders.delete("Host");
  upstreamHeaders.set("Authorization", `Bearer ${creds.access_token}`);

  // DashScope / Qwen OpenAI-compatible APIs may rely on these headers.
  // Source: https://github.com/QwenLM/qwen-code/blob/105ad743faa59f0a8f575f859d3b5869ff00acb9/packages/core/src/core/openaiContentGenerator/provider/dashscope.ts
  const dsUserAgent = "openai-qwen-worker/1.0";
  upstreamHeaders.set("User-Agent", dsUserAgent);
  upstreamHeaders.set("X-DashScope-CacheControl", "enable");
  upstreamHeaders.set("X-DashScope-UserAgent", dsUserAgent);
  upstreamHeaders.set("X-DashScope-AuthType", "QWEN_OAUTH");

  if (overrideBodyText !== undefined) {
    // Prevent mismatched content-length after body rewriting.
    upstreamHeaders.delete("Content-Length");
  }

  const upstreamInit = {
    method: request.method,
    headers: upstreamHeaders,
    body:
      request.method === "GET" || request.method === "HEAD"
        ? undefined
        : (overrideBodyText !== undefined ? overrideBodyText : request.body),
  };

  const upstreamResp = await fetch(upstreamUrl.toString(), upstreamInit);

  if (mapToResponses && upstreamResp.ok) {
    const ct = upstreamResp.headers.get("Content-Type") || "";
    const isSSE = ct.includes("text/event-stream");
    const headers = new Headers(upstreamResp.headers);
    headers.set("Cache-Control", "no-store");

    if (isSSE) {
      const body = upstreamResp.body
        .pipeThrough(new TextDecoderStream())
        .pipeThrough(new TransformStream({ transform: mapChatSSEToResponsesSSE, buffer: "" }))
        .pipeThrough(new TextEncoderStream());
      headers.set("Content-Type", "text/event-stream");
      return withCORS(new Response(body, { status: upstreamResp.status, statusText: upstreamResp.statusText, headers }));
    }

    const txt = await upstreamResp.text();
    const mapped = mapChatToResponsesJSON(txt);
    headers.set("Content-Type", "application/json; charset=utf-8");
    return withCORS(new Response(mapped, { status: upstreamResp.status, statusText: upstreamResp.statusText, headers }));
  }

  // Some OpenAI-compatible upstreams (including Qwen) may stream cumulative text in
  // choices[].delta.content ("text so far") rather than true deltas. Streaming clients
  // that concatenate deltas will then duplicate the prefix.
  // Normalize SSE for chat completions to always emit incremental deltas.
  if (upstreamResp.ok) {
    const ct = upstreamResp.headers.get("Content-Type") || "";
    const isSSE = ct.includes("text/event-stream");
    if (isSSE && upstreamPath === "/chat/completions") {
      const headers = new Headers(upstreamResp.headers);
      headers.set("Cache-Control", "no-store");
      headers.set("Content-Type", "text/event-stream");

      const body = upstreamResp.body
        .pipeThrough(new TextDecoderStream())
        .pipeThrough(
          new TransformStream({
            transform: normalizeChatCompletionsSSEToDeltas,
            flush: flushNormalizeChatCompletionsSSE,
            buffer: "",
            // Map of choiceIndex -> assistant content emitted so far
            seenByChoice: {},
          }),
        )
        .pipeThrough(new TextEncoderStream());

      return withCORS(
        new Response(body, {
          status: upstreamResp.status,
          statusText: upstreamResp.statusText,
          headers,
        }),
      );
    }
  }

  return withCORS(upstreamResp);
}

function handleOPTIONS() {
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "*",
      "Access-Control-Allow-Headers": "*",
    },
  });
}

function withCORS(response) {
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Headers", "*");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function getBearerToken(request) {
  const auth = request.headers.get("Authorization");
  if (!auth) return null;
  const parts = auth.split(" ");
  if (parts.length !== 2) return null;
  if (parts[0].toLowerCase() !== "bearer") return null;
  return parts[1];
}

function normalizeEndpoint(resourceUrl) {
  // Align behavior with Qwen Code: add protocol if missing, ensure /v1 suffix.
  // Source: https://github.com/QwenLM/qwen-code/blob/105ad743faa59f0a8f575f859d3b5869ff00acb9/packages/core/src/qwen/qwenContentGenerator.ts
  const baseEndpoint = (resourceUrl || DEFAULT_RESOURCE_URL).trim();
  const withProto = /^https?:\/\//i.test(baseEndpoint)
    ? baseEndpoint
    : `https://${baseEndpoint}`;
  const trimmed = withProto.replace(/\/+$/g, "");
  return trimmed.endsWith("/v1") ? trimmed : `${trimmed}/v1`;
}

async function handleTokenSubmit(request, env) {
  const kv = env.KV;
  if (!kv) {
    return new Response("KV binding 'KV' is missing (see wrangler.toml)", { status: 500 });
  }

  /** @type {{access_token?: string, refresh_token?: string, resource_url?: string, expiry_date?: number | string, token_type?: string}} */
  let payload;
  try {
    payload = await readBodyAsObject(request);
  } catch (e) {
    return new Response(`Invalid request body: ${e.message}`, { status: 400 });
  }

  const access_token = (payload.access_token || "").trim();
  const refresh_token = (payload.refresh_token || "").trim();
  const resource_url = (payload.resource_url || "").trim();
  if (!access_token || !refresh_token) {
    return new Response("Both access_token and refresh_token are required", { status: 400 });
  }

  // Persist expiry_date as required.
  // Prefer explicit expiry_date from the user (e.g. from ~/.qwen/oauth_creds.json).
  // Otherwise, try to infer it from a JWT access token "exp" claim.
  const explicitExpiry = payload.expiry_date;
  let expiry_date =
    explicitExpiry !== undefined && explicitExpiry !== null && String(explicitExpiry).trim() !== ""
      ? Number(explicitExpiry)
      : inferExpiryDateFromJWT(access_token);

  if (!Number.isFinite(expiry_date) || expiry_date <= 0) {
    return new Response(
      "expiry_date is required (milliseconds since epoch) if it cannot be inferred from access_token",
      { status: 400 },
    );
  }

  const creds = /** @type {QwenCredentialsRecord} */ ({
    access_token,
    refresh_token,
    token_type: (payload.token_type || "Bearer").trim() || "Bearer",
    resource_url: resource_url || DEFAULT_RESOURCE_URL,
    expiry_date,
  });

  const endpoint = normalizeEndpoint(creds.resource_url);

  const token = generateOpenAIToken();
  await kv.put(`oai:${token}`, JSON.stringify(creds));

  return new Response(
    JSON.stringify({
      token,
      endpoint,
      expiry_date: creds.expiry_date,
    }),
    {
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
      },
    },
  );
}

async function readBodyAsObject(request) {
  const contentType = request.headers.get("Content-Type") || "";
  if (contentType.includes("application/json")) {
    const text = await request.text();
    if (!text) return {};
    return JSON.parse(text);
  }
  if (contentType.includes("application/x-www-form-urlencoded")) {
    const text = await request.text();
    const params = new URLSearchParams(text);
    return {
      access_token: params.get("access_token") || "",
      refresh_token: params.get("refresh_token") || "",
      resource_url: params.get("resource_url") || "",
      expiry_date: params.get("expiry_date") || "",
      token_type: params.get("token_type") || "",
    };
  }
  throw new Error(`Unsupported Content-Type: ${contentType || "(missing)"}`);
}

function inferExpiryDateFromJWT(accessToken) {
  // Best-effort expiry inference.
  // Many OAuth providers use JWT access tokens with an "exp" claim (seconds since epoch).
  try {
    const parts = String(accessToken).split(".");
    if (parts.length < 2) return null;
    const payload = parts[1];
    const padded = payload
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(payload.length + ((4 - (payload.length % 4)) % 4), "=");
    const json = JSON.parse(atob(padded));
    const exp = json?.exp;
    const expNum = typeof exp === "number" ? exp : Number(exp);
    if (!Number.isFinite(expNum) || expNum <= 0) return null;
    return expNum * 1000;
  } catch {
    return null;
  }
}

function generateOpenAIToken() {
  // Keep OpenAI-ish prefix for compatibility with existing clients.
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return `sk-qwen-${base64UrlEncode(bytes)}`;
}

function base64UrlEncode(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function ensureFreshCredentials(creds, kv, recordKey) {
  if (!creds.expiry_date || !creds.refresh_token) {
    return creds;
  }

  const now = Date.now();
  if (now < creds.expiry_date - TOKEN_REFRESH_BUFFER_MS) {
    return creds;
  }

  const refreshed = await refreshAccessToken(creds.refresh_token);
  if (!refreshed.ok) {
    // Credentials are no longer valid.
    throw new Error(refreshed.error);
  }

  const updated = /** @type {QwenCredentialsRecord} */ ({
    access_token: refreshed.access_token,
    refresh_token: refreshed.refresh_token,
    token_type: refreshed.token_type,
    resource_url: refreshed.resource_url || creds.resource_url || DEFAULT_RESOURCE_URL,
    expiry_date: refreshed.expiry_date,
  });

  await kv.put(recordKey, JSON.stringify(updated));
  return updated;
}

async function refreshAccessToken(refresh_token) {
  // OAuth token refresh is based on the official Qwen OAuth2 client.
  // Source: https://github.com/QwenLM/qwen-code/blob/105ad743faa59f0a8f575f859d3b5869ff00acb9/packages/core/src/qwen/qwenOAuth2.ts
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token,
    client_id: QWEN_OAUTH_CLIENT_ID,
  });

  const resp = await fetch(QWEN_OAUTH_TOKEN_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json",
    },
    body,
  });

  const text = await resp.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!resp.ok) {
    return {
      ok: false,
      status: resp.status,
      error: `OAuth refresh failed: ${resp.status} ${resp.statusText}\n${text}`,
    };
  }

  if (!json || !json.access_token || !json.token_type || !json.expires_in) {
    return {
      ok: false,
      status: 400,
      error: `OAuth refresh returned unexpected payload: ${text}`,
    };
  }

  return {
    ok: true,
    access_token: json.access_token,
    token_type: json.token_type,
    refresh_token: json.refresh_token || refresh_token,
    resource_url: json.resource_url,
    expiry_date: Date.now() + Number(json.expires_in) * 1000,
  };
}

// --- Responses API compatibility helpers ---------------------------------

function mapFinishReason(fr) {
  switch (fr) {
    case "stop":
      return "end_turn";
    case "length":
      return "max_output_tokens";
    case "content_filter":
      return "content_filter";
    case "tool_calls":
      return "tool_use";
    default:
      return fr || undefined;
  }
}

function unsupportedError(message) {
  const e = new Error(message);
  e.status = 422;
  return e;
}

function convertResponsesToChatBody(responsesBody) {
  let input = responsesBody?.input;
  if (typeof input === "string") {
    input = [{ role: "user", content: [{ type: "input_text", text: input }] }];
  } else if (!Array.isArray(input)) {
    input = input ? [input] : [];
  }

  const messages = [];
  const unsupported = new Set();

  for (const raw of input) {
    if (!raw) continue;
    const role = raw.role || "user";
    const contentParts = [];

    let parts = raw.content;
    if (typeof parts === "string") {
      parts = [{ type: "input_text", text: parts }];
    } else if (parts && !Array.isArray(parts)) {
      parts = [parts];
    } else if (!parts) {
      parts = [];
    }

    for (const p of parts) {
      if (!p) continue;
      const t = typeof p.type === "string" ? p.type : undefined;

      if (t === "input_text" || t === "text") {
        const text = p.text ?? p.content ?? "";
        if (text !== "") contentParts.push({ type: "text", text });
        continue;
      }

      if (t === "input_image" || t === "image") {
        const imageUrl = p.image_url || p.url || p.image || "";
        if (imageUrl) contentParts.push({ type: "image_url", image_url: { url: imageUrl } });
        continue;
      }

      if (t) unsupported.add(t);
    }

    if (contentParts.length > 0) {
      messages.push({ role, content: contentParts });
    }
  }

  if (messages.length === 0) {
    const list = [...unsupported];
    if (list.length > 0) {
      throw unsupportedError(
        "No supported content in Responses input; unsupported types: " + list.join(", "),
      );
    }
    throw unsupportedError("No supported content in Responses input");
  }

  const chatBody = {
    model: responsesBody?.model,
    messages,
    stream: !!responsesBody?.stream,
  };
  if (responsesBody?.temperature !== undefined) chatBody.temperature = responsesBody.temperature;
  if (responsesBody?.top_p !== undefined) chatBody.top_p = responsesBody.top_p;
  const maxTokens = responsesBody?.max_output_tokens ?? responsesBody?.max_tokens;
  if (maxTokens !== undefined) chatBody.max_tokens = maxTokens;
  return { chatBody };
}

function mapChatToResponsesJSON(chatText) {
  try {
    const chat = JSON.parse(chatText);
    const outputs = [];
    let stopReason;

    if (Array.isArray(chat?.choices) && chat.choices.length > 0) {
      const choice = chat.choices[0];
      stopReason = mapFinishReason(choice?.finish_reason);
      const msg = choice?.message;
      if (msg) {
        if (typeof msg.content === "string") {
          if (msg.content) outputs.push({ type: "output_text", text: msg.content });
        } else if (Array.isArray(msg.content)) {
          for (const p of msg.content) {
            if (!p) continue;
            if (p.type === "text" && typeof p.text === "string") {
              if (p.text) outputs.push({ type: "output_text", text: p.text });
            } else if (p.type === "image_url" && p.image_url) {
              const url = typeof p.image_url === "string" ? p.image_url : p.image_url.url;
              if (url) outputs.push({ type: "output_image", image_url: url });
            }
          }
        }
      }
    }

    const resp = {
      id: chat.id || crypto.randomUUID(),
      object: "response",
      model: chat.model,
      created: chat.created || Math.floor(Date.now() / 1000),
      output: outputs,
    };

    if (chat.usage) {
      const u = chat.usage;
      resp.usage = {
        input_tokens: u.prompt_tokens,
        output_tokens: u.completion_tokens,
        total_tokens: u.total_tokens,
      };
    }

    if (stopReason) {
      resp.stop_reason = stopReason;
      resp.status = "completed";
    }

    return JSON.stringify(resp);
  } catch {
    return chatText;
  }
}

const RESPONSES_DELIMITER = "\n\n";

const CHAT_SSE_DELIMITER = "\n\n";

function normalizeChatCompletionsSSEToDeltas(chunk, controller) {
  if (!chunk) return;

  this.buffer = (this.buffer || "") + chunk;
  const events = this.buffer.split(CHAT_SSE_DELIMITER);
  for (let i = 0; i < events.length - 1; i++) {
    const out = normalizeChatCompletionsSSEEvent.call(this, events[i]);
    if (out) controller.enqueue(out);
  }
  this.buffer = events[events.length - 1];
}

function flushNormalizeChatCompletionsSSE(controller) {
  if (!this.buffer) return;
  const out = normalizeChatCompletionsSSEEvent.call(this, this.buffer);
  if (out) controller.enqueue(out);
  this.buffer = "";
}

function normalizeChatCompletionsSSEEvent(eventText) {
  if (!eventText) return;

  // Preserve non-data lines (e.g., "event:") as-is.
  const lines = String(eventText).split("\n");
  let changed = false;

  const outLines = lines.map((line) => {
    if (!line.startsWith("data: ")) return line;

    const payload = line.substring(6);
    if (payload.trim() === "[DONE]") {
      return line;
    }

    let json;
    try {
      json = JSON.parse(payload);
    } catch {
      return line;
    }

    if (!json || !Array.isArray(json.choices)) {
      return line;
    }

    this.seenByChoice = this.seenByChoice || {};

    for (let i = 0; i < json.choices.length; i++) {
      const choice = json.choices[i];
      if (!choice) continue;

      const idx = (typeof choice.index === "number" ? choice.index : i);
      const delta = choice.delta;
      if (!delta) continue;

      const content = delta.content;
      if (typeof content !== "string" || content.length === 0) continue;

      const prev = typeof this.seenByChoice[idx] === "string" ? this.seenByChoice[idx] : "";

      // If the upstream sends cumulative "text so far", it will start with what we've already emitted.
      if (content.startsWith(prev)) {
        const nextDelta = content.substring(prev.length);
        choice.delta.content = nextDelta;
        this.seenByChoice[idx] = content;
      } else {
        // Otherwise, assume it's already a delta.
        this.seenByChoice[idx] = prev + content;
      }
    }

    changed = true;
    return "data: " + JSON.stringify(json);
  });

  // Only rewrite if we had a valid JSON payload; otherwise pass through unchanged.
  const result = outLines.join("\n");
  return (changed ? result : eventText) + CHAT_SSE_DELIMITER;
}

function mapChatSSEToResponsesSSE(chunk, controller) {
  chunk = chunk;
  if (!chunk) {
    if (this.buffer) {
      const flushed = flushChatLineToResponses.call(this, this.buffer);
      if (flushed) controller.enqueue(flushed);
    }
    const stop = this.stopReason ? `,"stop_reason":"${this.stopReason}"` : "";
    controller.enqueue("data: {\"type\":\"response.completed\"" + stop + "}" + RESPONSES_DELIMITER);
    controller.enqueue("\n");
    controller.terminate();
    return;
  }

  this.buffer = (this.buffer || "") + chunk;
  const lines = this.buffer.split(RESPONSES_DELIMITER);
  for (let i = 0; i < lines.length - 1; i++) {
    const out = flushChatLineToResponses.call(this, lines[i]);
    if (out) controller.enqueue(out);
  }
  this.buffer = lines[lines.length - 1];
}

function flushChatLineToResponses(line) {
  if (!line) return;
  if (!line.startsWith("data: ")) return;
  const payload = line.substring(6);
  if (payload === "[DONE]") {
    const stop = this.stopReason ? `,"stop_reason":"${this.stopReason}"` : "";
    return "data: {\"type\":\"response.completed\"" + stop + "}" + RESPONSES_DELIMITER;
  }

  try {
    const json = JSON.parse(payload);
    const deltas = [];

    if (Array.isArray(json?.choices)) {
      for (const c of json.choices) {
        const d = c?.delta;
        if (!d) continue;

        const content = d.content;
        if (typeof content === "string" && content) deltas.push(content);
        else if (Array.isArray(content)) {
          for (const p of content) {
            if (p?.type === "text" && typeof p.text === "string") deltas.push(p.text);
          }
        }

        if (!this.stopReason && c?.finish_reason) {
          this.stopReason = mapFinishReason(c.finish_reason);
        }
      }
    }

    if (deltas.length > 0) {
      const respEvt = { type: "response.output_text.delta", delta: deltas.join("") };
      return "data: " + JSON.stringify(respEvt) + RESPONSES_DELIMITER;
    }
  } catch {
    return;
  }
}
