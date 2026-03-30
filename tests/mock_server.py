"""Mock LLM server that logs ALL received requests for verification."""
import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

LOG_DIR = "/tmp/dam_test_requests"
os.makedirs(LOG_DIR, exist_ok=True)

counter = 0

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global counter
        counter += 1
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")

        # Log every request with a sequence number
        with open(f"{LOG_DIR}/{counter:04d}.json", "w") as f:
            f.write(body)

        # Also write the latest for backward compat
        with open("/tmp/dam_test_received.json", "w") as f:
            f.write(body)

        try:
            req = json.loads(body)
            messages = req.get("messages", [])
            user_msg = next((m["content"] for m in messages if m["role"] == "user"), body)
        except:
            user_msg = body

        resp = json.dumps({
            "id": "msg_test123",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": f"I received: {user_msg}"}],
            "model": "mock-claude",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 20}
        })

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp.encode())

    def log_message(self, format, *args):
        pass

HTTPServer(("127.0.0.1", 9999), Handler).serve_forever()
