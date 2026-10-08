#!/usr/bin/env python3
"""Stand-in for Prisma AIRS API Intercept (POST /v1/scan/sync/request).

Request/response shapes follow pan.dev/prisma-airs/api/airuntimesecurity. Detection is
crude keyword/regex logic; the point is the contract, not the ML. Swap AIRS_URL to
https://service.api.aisecurity.paloaltonetworks.com and use a real x-pan-token to go live.
"""
import json, os, re, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("MOCK_AIRS_TOKEN", "mock-token")
INJECTION = re.compile(r"ignore (all )?(previous|prior) instructions|disregard your (rules|system prompt)|you are now DAN", re.I)
TOXIC = re.compile(r"\b(build a bomb|make a weapon)\b", re.I)
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CARD = re.compile(r"\b(?:\d[ -]?){13,16}\b")
BAD_URL = re.compile(r"https?://[^\s]*(malware|phish)[^\s]*", re.I)


def mask(text):
    locs = []
    for rx, name in ((SSN, "ssn"), (CARD, "credit-card")):
        for m in rx.finditer(text):
            locs.append((m.start(), m.end(), name))
    out = list(text)
    for s, e, _ in locs:
        out[s:e] = ["X"] * (e - s)
    dets = {}
    for s, e, n in locs:
        dets.setdefault(n, []).append([s, e])
    return "".join(out), [{"pattern": n, "locations": l} for n, l in dets.items()]


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        self._send(200, {"ok": True})

    def do_POST(self):
        if self.path != "/v1/scan/sync/request":
            return self._send(404, {"error": "not found"})
        if self.headers.get("x-pan-token") != TOKEN:
            return self._send(401, {"error": {"message": "Not Authenticated"}})
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        c = req["contents"][0]
        resp = {"report_id": "R" + uuid.uuid4().hex, "scan_id": str(uuid.uuid4()), "tr_id": req.get("tr_id"),
                "profile_id": str(uuid.uuid5(uuid.NAMESPACE_DNS, req["ai_profile"].get("profile_name", ""))),
                "profile_name": req["ai_profile"].get("profile_name"), "category": "benign", "action": "allow"}
        if "prompt" in c:
            t = c["prompt"]
            det = {"injection": bool(INJECTION.search(t)), "toxic_content": bool(TOXIC.search(t)),
                   "url_cats": bool(BAD_URL.search(t)), "dlp": bool(SSN.search(t) or CARD.search(t)),
                   "malicious_code": False, "topic_violation": False}
            resp["prompt_detected"] = det
            if det["dlp"]:
                data, pd = mask(t)
                resp["prompt_masked_data"] = {"data": data, "pattern_detections": pd}
        if "response" in c:
            t = c["response"]
            det = {"dlp": bool(SSN.search(t) or CARD.search(t)), "url_cats": bool(BAD_URL.search(t)),
                   "db_security": False, "ungrounded": False}
            resp["response_detected"] = det
            if det["dlp"]:
                data, pd = mask(t)
                resp["response_masked_data"] = {"data": data, "pattern_detections": pd}
        if any((resp.get("prompt_detected") or {}).values()) or any((resp.get("response_detected") or {}).values()):
            resp["category"], resp["action"] = "malicious", "block"
        print(json.dumps({"scan": req.get("tr_id"), "profile": resp["profile_name"], "app_user": (req.get("metadata") or {}).get("app_user"), "action": resp["action"],
                          "prompt_detected": resp.get("prompt_detected"), "response_detected": resp.get("response_detected")}), flush=True)
        self._send(200, resp)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever()
