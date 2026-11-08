"""CPU-heavy HTTP victim (port 8082). 임팩트 스코어링 테스트용."""
#!/usr/bin/env python3
# CPU-heavy victim: measures impact score under attack
import http.server, threading, os, time
class HeavyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # CPU work: ~2ms
        x = 0
        for i in range(200000):
            x += i * i
        body = b'ok:%d' % x
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
port = int(os.environ.get('VICTIM_PORT', '8082'))
print(f'heavy-victim listening on {port}', flush=True)
http.server.ThreadingHTTPServer(('127.0.0.1', port), HeavyHandler).serve_forever()
