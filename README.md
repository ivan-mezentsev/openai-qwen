# openai-qwen

Cloudflare Worker that provides an **OpenAI-compatible API** backed by **Qwen OAuth credentials**.

You paste `access_token` + `refresh_token` once via `/token`. The worker returns a generated
OpenAI-style API key (looks like `sk-qwen-...`). You can use that key "forever" — the worker
automatically refreshes the Qwen access token behind the scenes.

## Deploy

1. Create a Cloudflare account.

    Install Wrangler:

    ```bash
    npm install -g wrangler
    ```

    Log in to Cloudflare:

    ```bash
    wrangler login
    ```

2. Create a KV namespace (binding name must be `KV`).

    ```shell
    wrangler kv namespace create KV
    ```

    Update the KV `id` in `wrangler.toml` if you create a new namespace.

    ```toml
    [[kv_namespaces]]
    binding = "KV"
    id = "<Your-id>"
    ```

3. Deploy with Wrangler.

    ```shell
    wrangler deploy
    ```

## Get your OpenAI-compatible token

1. Open:

`https://<your-worker-domain>/token`

1. Paste `access_token` and `refresh_token` (for example from `~/.qwen/oauth_creds.json`).
  Optionally, paste `resource_url` if your creds file includes it.
1. Click “Save”.
1. Copy the returned token `sk-qwen-...`.

## Use

Set your client to point to this worker:

- Base URL: `https://<your-worker-domain>/v1`
- API Key: the generated `sk-qwen-...`

Example:

```sh
curl https://<your-worker-domain>/v1/chat/completions \
  -H "Authorization: Bearer sk-qwen-..." \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen3-coder-plus","messages":[{"role":"user","content":"Hello!"}]}'
```

## API compatibility

- All requests are proxied to the Qwen OpenAI-compatible base URL derived from `resource_url`.
- `/v1/responses` is supported as a compatibility shim: the worker converts it to `/v1/chat/completions`
  and maps the result back to a minimal Responses schema.

## Security notes

- Treat `/token` as an admin page: it stores OAuth credentials in KV.
- Treat `sk-qwen-...` as a secret API key.
