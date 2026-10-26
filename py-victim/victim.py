#!/usr/bin/env python3
# minimal victim for local DoS lab
import http.server, threading, os
class QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
port = int(os.environ.get('VICTIM_PORT','8081'))
http.server.HTTPServer(('127.0.0.1',port),QuietHandler).serve_forever()
