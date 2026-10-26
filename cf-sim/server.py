#!/usr/bin/env python3
"""
cf-sim v0.4: Cloudflare-like edge simulator for local DoS lab.
- TLS 1.3 (self-signed cert auto-generated)
- HTTP/1.1 with token-bucket rate limiting
- /metrics JSON endpoint
- /echo path for payload measurement
- keep-alive connection reuse
- per-IP rate limiting (simple token bucket by peer)
"""
import asyncio, ssl, os, json, time, subprocess
from pathlib import Path

HERE = Path(__file__).parent
CERT = HERE / 'cert.pem'
KEY = HERE / 'key.pem'
PORT = int(os.environ.get('CF_SIM_PORT', '8443'))
RATE_LIMIT = int(os.environ.get('CF_SIM_RATE_LIMIT', '5000'))  # global req/sec
PER_IP_RATE = int(os.environ.get('CF_SIM_PER_IP_RATE', '1000'))  # per-IP req/sec
PER_IP_BURST = int(os.environ.get('CF_SIM_PER_IP_BURST', '50'))

def ensure_cert():
    if CERT.exists() and KEY.exists():
        return
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-keyout',str(KEY),
                    '-out',str(CERT),'-days','365','-nodes','-subj','/CN=localhost'],
                   check=True, capture_output=True)

ensure_cert()

class Metrics:
    def __init__(self):
        self.requests = 0
        self.received_bytes = 0
        self.sent_bytes = 0
        self.limited = 0
        self.peak_concurrent = 0
        self.active = 0
        self.started = time.time()
m = Metrics()

class TokenBucket:
    def __init__(self, rate, burst=None):
        self.rate = rate
        self.burst = burst if burst is not None else rate
        self.tokens = self.burst
        self.last = time.time()
        self.lock = asyncio.Lock()
    async def consume(self, n=1):
        async with self.lock:
            now = time.time()
            self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens >= n:
                self.tokens -= n
                return True
            return False

global_bucket = TokenBucket(RATE_LIMIT, RATE_LIMIT)
per_ip_buckets = {}

async def get_bucket(peer):
    if peer not in per_ip_buckets:
        per_ip_buckets[peer] = TokenBucket(PER_IP_RATE, PER_IP_BURST)
    return per_ip_buckets[peer]

async def read_headers(reader):
    request_line = await asyncio.wait_for(reader.readline(), timeout=1.0)
    if not request_line:
        return None, {}, 0
    headers = {}
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=1.0)
        if line in (b'\r\n', b'\n', b''):
            break
        k, _, v = line.decode('latin1').partition(':')
        headers[k.strip().lower()] = v.strip()
    return request_line, headers, len(request_line)

async def handle(reader, writer):
    peer = writer.get_extra_info('peername')
    m.active += 1
    m.peak_concurrent = max(m.peak_concurrent, m.active)
    try:
        while True:
            ip_bucket = await get_bucket(peer)
            if not (await global_bucket.consume() and await ip_bucket.consume()):
                m.limited += 1
                writer.write(b'HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n')
                await writer.drain()
                continue
            result = await read_headers(reader)
            if result is None:
                break
            request_line, headers, line_len = result
            content_length = int(headers.get('content-length', '0'))
            body = b''
            if content_length:
                body = await asyncio.wait_for(reader.readexactly(content_length), timeout=1.0)
            m.requests += 1
            m.received_bytes += line_len + len(body)
            path = request_line.decode('latin1').split(' ')[1] if b' ' in request_line else '/'
            if path == '/metrics':
                resp = json.dumps({**vars(m), 'now': time.time(), 'per_ip_buckets': len(per_ip_buckets)}).encode()
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(resp)).encode() + b'\r\n\r\n' + resp)
            elif path == '/echo':
                resp = body
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ' + str(len(resp)).encode() + b'\r\n\r\n' + resp)
            else:
                resp = b'cf-sim ok'
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ' + str(len(resp)).encode() + b'\r\n\r\n' + resp)
            m.sent_bytes += len(resp)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        m.active -= 1
        try:
            writer.close(); await writer.wait_closed()
        except Exception:
            pass

async def main():
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(str(CERT), str(KEY))
    server = await asyncio.start_server(handle, '127.0.0.1', PORT, ssl=ssl_ctx)
    print(f'cf-sim listening on {PORT}', flush=True)
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
