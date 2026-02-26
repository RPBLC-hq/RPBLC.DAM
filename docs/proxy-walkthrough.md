# Proxy Walkthrough: What Happens to Your Data

This walkthrough shows exactly what DAM does at each stage of a request. Every value shown below is from a real test run.

## The Scenario

You want an LLM to draft a meeting confirmation that includes contact details:

```
"I need you to draft a short confirmation message (2-3 sentences)
 for a meeting with John Smith. His email is john.smith@acme-corp.com
 and his phone is (555) 867-5309. Include his contact details in
 the confirmation."
```

Without DAM, the LLM provider receives and processes `john.smith@acme-corp.com` and `(555) 867-5309` in plaintext. With DAM running as a local proxy, here is what actually happens:

---

## Stage 1 — Pre-Proxy (what you send)

Your application sends a normal API request to `http://127.0.0.1:7828` instead of directly to the provider:

```bash
curl http://127.0.0.1:7828/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
  "model": "claude-3-haiku-20240307",
  "max_tokens": 300,
  "messages": [{
    "role": "user",
    "content": "I need you to draft a short confirmation message (2-3 sentences) for a meeting with John Smith. His email is john.smith@acme-corp.com and his phone is (555) 867-5309. Include his contact details in the confirmation."
  }]
}'
```

The request contains real PII: an email address and a phone number.

## Stage 2 — Pre-LLM (what the provider receives)

DAM intercepts the request, detects the PII, encrypts the original values in the local vault, and replaces them with typed references before forwarding upstream:

```json
{
  "model": "claude-3-haiku-20240307",
  "messages": [{
    "role": "user",
    "content": "I need you to draft a short confirmation message (2-3 sentences) for a meeting with John Smith. His email is [email:390fc7f8] and his phone is [phone:16cc16f0]. Include his contact details in the confirmation."
  }],
  "max_tokens": 300
}
```

The LLM **never sees** `john.smith@acme-corp.com` or `(555) 867-5309`. It only sees `[email:390fc7f8]` and `[phone:16cc16f0]` — typed references that tell it the *kind* of data without revealing the *value*.

## Stage 3 — Post-LLM (raw provider response)

The LLM reasons about the data types and composes a response using the references it was given:

```json
{
  "content": [{
    "type": "text",
    "text": "Meeting confirmed! I will send details to [email:390fc7f8] and call [phone:16cc16f0] to confirm attendance."
  }]
}
```

The response leaves the provider's servers with references only — no real PII in transit.

## Stage 4 — Post-Proxy (what you get back)

DAM intercepts the response, looks up the references in the local vault, decrypts the original values, and resolves them back before returning to your application:

```json
{
  "content": [{
    "type": "text",
    "text": "Meeting confirmed! I will send details to john.smith@acme-corp.com and call (555) 867-5309 to confirm attendance."
  }]
}
```

You see real values. The LLM never did.

---

## What the vault looks like

After the request, `dam vault list` shows the encrypted entries:

```
[email:390fc7f8] → email  (stored: 2025-02-26T02:53:56Z)
[phone:16cc16f0] → phone  (stored: 2025-02-26T02:53:56Z)
```

The actual values (`john.smith@acme-corp.com`, `(555) 867-5309`) are encrypted with per-entry AES-256-GCM keys. The master key lives in your OS keychain — never on disk.

## Summary

```
  You ──────► DAM Proxy ──────► LLM Provider ──────► DAM Proxy ──────► You

  john.smith    [email:390fc7f8]   [email:390fc7f8]    john.smith
  @acme-corp    [phone:16cc16f0]   [phone:16cc16f0]    @acme-corp
  .com                                                  .com
  (555)                                                 (555)
  867-5309                                              867-5309

              ▲ PII replaced        ▲ LLM responds      ▲ Refs resolved
              │ with refs           │ with refs          │ back to values
              │                     │                    │
              └─ Originals          └─ No real PII       └─ Decrypted
                 encrypted             ever leaves          from local
                 in local              your machine         vault
                 vault
```

No code changes required. Point your API client at DAM, and PII interception is automatic.

## Reproducing This Test

To verify this behavior yourself:

```bash
# 1. Install and initialize
cargo install --path crates/dam-cli
dam init

# 2. Start the proxy
dam serve

# 3. Send a request (in another terminal)
curl http://127.0.0.1:7828/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-3-haiku-20240307",
    "max_tokens": 300,
    "messages": [{
      "role": "user",
      "content": "Email john@example.com about the meeting at (555) 123-4567"
    }]
  }'
```

To inspect what DAM sends upstream, route through a local echo server with the `X-DAM-Upstream` header:

```bash
# Start a simple echo server (Python)
python -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        print(json.dumps(json.loads(body), indent=2))
        resp = json.dumps({'id':'test','type':'message','role':'assistant',
            'content':[{'type':'text','text':'echo'}],
            'model':'echo','stop_reason':'end_turn','stop_sequence':None,
            'usage':{'input_tokens':0,'output_tokens':0}}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

HTTPServer(('127.0.0.1', 9999), H).serve_forever()
" &

# Send through DAM, routed to the echo server
curl http://127.0.0.1:7828/v1/messages \
  -H "x-api-key: fake" \
  -H "anthropic-version: 2023-06-01" \
  -H "X-DAM-Upstream: http://127.0.0.1:9999" \
  -H "content-type: application/json" \
  -d '{"model":"test","max_tokens":100,"messages":[{"role":"user","content":"Email john@example.com"}]}'
```

The echo server's stdout will show the redacted payload — confirming no PII leaves DAM.
