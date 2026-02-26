# Upstream Routing

Use `X-DAM-Upstream` to override the configured upstream for a single request.

## Example (route OpenAI-format request to xAI)

```bash
curl http://127.0.0.1:7828/v1/chat/completions \
  -H "Authorization: Bearer $XAI_API_KEY" \
  -H "X-DAM-Upstream: https://api.x.ai" \
  -H "content-type: application/json" \
  -d '{"model":"grok-3","messages":[{"role":"user","content":"Hello"}]}'
```

## Global override via startup flag

```bash
dam serve --openai-upstream https://openrouter.ai/api
```

## Validation rules for `X-DAM-Upstream`

- allowed schemes: `http://`, `https://`
- credentials (`@`) are rejected
- query strings (`?`) and fragments (`#`) are rejected
- trailing slashes are normalized
- absent/empty header falls back to configured default

## Path-prefix behavior

Path prefixes are preserved:

- `X-DAM-Upstream: https://gateway.corp.com/openai`
- route `/v1/chat/completions`
- result target: `https://gateway.corp.com/openai/v1/chat/completions`
