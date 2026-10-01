#!/usr/bin/env python3
"""agentgateway guardrail webhook -> Prisma AIRS AI Runtime API Intercept adapter.

agentgateway calls POST /request (prompts) and POST /response (LLM output) per the
Guardrail Webhook API. We forward the text to AIRS /v1/scan/sync/request and map the
verdict back:  action=block -> RejectAction, masked data -> MaskAction, else PassAction.
Any AIRS error returns 502, and agentgateway's failureMode (FailClosed default) blocks.
"""
import json, os, sys, uuid, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AIRS_URL = os.environ.get("AIRS_URL", "https://service.api.aisecurity.paloaltonetworks.com").rstrip("/")
AIRS_TOKEN = os.environ["AIRS_API_KEY"]            # x-pan-token from Strata Cloud Manager
AIRS_PROFILE = os.environ.get("AIRS_PROFILE", "agentgateway-default")
APP_NAME = os.environ.get("AIRS_APP_NAME", "agentgateway")
TIMEOUT = float(os.environ.get("AIRS_TIMEOUT_SECONDS", "5"))


def log(**kv):
    print(json.dumps(kv), flush=True)


def airs_scan(contents, headers):
    tr_id = headers.get("x-request-id") or str(uuid.uuid4())
    payload = {
        "tr_id": tr_id,
        "ai_profile": {"profile_name": AIRS_PROFILE},
        "metadata": {
            "app_name": APP_NAME,
            "app_user": headers.get("x-user-id", "unknown"),
            "ai_model": headers.get("x-ai-model", "unknown"),
        },
        "contents": [contents],
    }
    req = urllib.request.Request(
        f"{AIRS_URL}/v1/scan/sync/request",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json", "x-pan-token": AIRS_TOKEN},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.load(r)


def verdict_summary(v, key):
    hits = [k for k, on in (v.get(key) or {}).items() if on]
    return ",".join(hits) or "none"


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, {"ok": True})

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        hdrs = {k.lower(): v for k, v in self.headers.items()}
        try:
            if self.path == "/request":
                self._send(200, self.scan_prompt(req["body"], hdrs))
            elif self.path == "/response":
                self._send(200, self.scan_response(req["body"], hdrs))
            else:
                self._send(404, {"error": "not found"})
        except Exception as e:  # AIRS unreachable / bad token / timeout
            log(event="airs_error", path=self.path, error=str(e))
            self._send(502, {"error": f"prisma airs scan failed: {e}"})

    def scan_prompt(self, body, hdrs):
        msgs = body.get("messages", [])
        # Scan the newest user turn as the prompt; earlier turns go in as context.
        idx = max((i for i, m in enumerate(msgs) if m.get("role") == "user"), default=None)
        if idx is None:
            return {"action": {"reason": "no user message"}}
        contents = {"prompt": msgs[idx]["content"]}
        history = "\n".join(f'{m["role"]}: {m["content"]}' for i, m in enumerate(msgs) if i != idx)
        if history:
            contents["context"] = history[-100_000:]
        v = airs_scan(contents, hdrs)
        log(event="airs_verdict", phase="prompt", action=v.get("action"), category=v.get("category"),
            detected=verdict_summary(v, "prompt_detected"), scan_id=v.get("scan_id"), report_id=v.get("report_id"))
        masked = (v.get("prompt_masked_data") or {}).get("data")
        if masked:
            msgs[idx]["content"] = masked
            return {"action": {"body": {"messages": msgs}, "reason": f"Prisma AIRS masked: {verdict_summary(v, 'prompt_detected')}"}}
        if v.get("action") == "block":
            return {"action": {"body": f"Blocked by Prisma AIRS ({verdict_summary(v, 'prompt_detected')}). scan_id={v.get('scan_id')}",
                               "status_code": 403, "reason": "prisma-airs"}}
        return {"action": {"reason": f"Prisma AIRS allow scan_id={v.get('scan_id')}"}}

    def scan_response(self, body, hdrs):
        choices = body.get("choices", [])
        masked_any, blocked = False, None
        for c in choices:
            v = airs_scan({"response": c["message"]["content"]}, hdrs)
            log(event="airs_verdict", phase="response", action=v.get("action"), category=v.get("category"),
                detected=verdict_summary(v, "response_detected"), scan_id=v.get("scan_id"), report_id=v.get("report_id"))
            masked = (v.get("response_masked_data") or {}).get("data")
            if masked:
                c["message"]["content"], masked_any = masked, True
            elif v.get("action") == "block":
                blocked = v
        # The response webhook has no Reject action; a blocked choice is blanked out
        # (the spec says: "If content needs to be deleted, set an empty content field").
        if blocked:
            for c in choices:
                c["message"]["content"] = f"[Response withheld by Prisma AIRS: {verdict_summary(blocked, 'response_detected')}]"
            return {"action": {"body": {"choices": choices}, "reason": "Prisma AIRS blocked response"}}
        if masked_any:
            return {"action": {"body": {"choices": choices}, "reason": "Prisma AIRS masked response"}}
        return {"action": {"reason": "Prisma AIRS allow"}}

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    log(event="start", airs_url=AIRS_URL, profile=AIRS_PROFILE, port=port)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
