#!/usr/bin/env python3
"""
cf-sim v0.7: Cloudflare-like edge simulator for local DoS lab.
- TLS 1.3 (self-signed cert auto-generated)
- HTTP/1.1 with token-bucket rate limiting (per-IP + global)
- HTTP/2 support via h2 (separate port with ALPN)
- /metrics JSON endpoint
- /echo path for payload measurement
- keep-alive connection reuse
- 429 responses: no Content-Length, no body (faster for attacker)
- Rate limits configurable via env vars
"""
import asyncio, ssl, os, json, time, subprocess
from pathlib import Path
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import RequestReceived, StreamEnded
from h2.exceptions import ProtocolError

HERE = Path(__file__).parent
CERT = HERE / 'cert.pem'
KEY = HERE / 'key.pem'
PORT = int(os.environ.get('CF_SIM_PORT', '8443'))
RATE_LIMIT = int(os.environ.get('CF_SIM_RATE_LIMIT', '5000'))
PER_IP_RATE = int(os.environ.get('CF_SIM_PER_IP_RATE', '1000'))
PER_IP_BURST = int(os.environ.get('CF_SIM_PER_IP_BURST', '50'))

def ensure_cert():
    """TLS 인증서/키 생성 (없으면 자동 생성)."""
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
    """per-IP 토큰 버킷 반환 (없으면 생성)."""
    if peer not in per_ip_buckets:
        per_ip_buckets[peer] = TokenBucket(PER_IP_RATE, PER_IP_BURST)
    return per_ip_buckets[peer]

async def read_headers(reader):
    """HTTP 요청 헤더 읽기."""
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

async def handle_http1(reader, writer, peer):
    while True:
        ip_bucket = await get_bucket(peer)
        if not (await global_bucket.consume() and await ip_bucket.consume()):
            m.limited += 1
            # 429: minimal response, no Content-Length, no body
            writer.write(b'HTTP/1.1 429 Too Many Requests\r\n\r\n')
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

def handle_h2_event(conn, event, writer, peer):
    """H2 이벤트 처리 (요청 수신 → 200 OK 응답)."""
    if isinstance(event, RequestReceived):
        headers = dict(event.headers)
        path = headers.get(':path', '/')
        stream_id = event.stream_id
        if path == '/metrics':
            body = json.dumps({**vars(m), 'now': time.time(), 'per_ip_buckets': len(per_ip_buckets)}).encode()
            conn.send_headers(stream_id, [(b':status', b'200'), (b'content-type', b'application/json'), (b'content-length', str(len(body)).encode())], end_stream=False)
            conn.send_data(stream_id, body, end_stream=True)
        elif path == '/echo':
            body = b''
            conn.send_headers(stream_id, [(b':status', b'200'), (b'content-type', b'application/octet-stream'), (b'content-length', b'0')], end_stream=False)
            conn.send_data(stream_id, body, end_stream=True)
        else:
            body = b'cf-sim h2 ok'
            conn.send_headers(stream_id, [(b':status', b'200'), (b'content-type', b'text/plain'), (b'content-length', str(len(body)).encode())], end_stream=False)
            conn.send_data(stream_id, body, end_stream=True)
        m.requests += 1
        m.received_bytes += 100
        m.sent_bytes += len(body)
        # Do NOT send here - the main loop will handle it
    else:
        pass

async def handle_h2(reader, writer, peer):
    config = H2Configuration(client_side=False)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    # Send initial SETTINGS and wait for client SETTINGS before reading requests
    initial = conn.data_to_send()
    writer.write(initial)
    await writer.drain()
    
    # Wait for client's SETTINGS frame
    try:
        client_data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
        conn.receive_data(client_data)
        # ACK client SETTINGS
        if conn.data_to_send():
            ack = conn.data_to_send()
            writer.write(ack)
            await writer.drain()
    except asyncio.TimeoutError:
        pass
    
    # Set TCP_NODELAY to disable Nagle's algorithm for lower latency
    sock = writer.transport.get_extra_info('socket')
    if sock:
        import socket
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    m.active += 1
    m.peak_concurrent = max(m.peak_concurrent, m.active)
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65535), timeout=5.0)
            if not data:
                break
            try:
                events = conn.receive_data(data)
                # Process all events first
                for event in events:
                    handle_h2_event(conn, event, writer, peer)
                # Then send all pending data at once
                out = conn.data_to_send()
                if out:
                    writer.write(out)
                    await writer.drain()
            except ProtocolError:
                break
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        m.active -= 1
        try:
            writer.close(); await writer.wait_closed()
        except Exception:
            pass

def make_ssl_ctx(protocol):
    """TLS 컨텍스트 생성 (SNI 기반)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERT), str(KEY))
    if protocol == 'h2':
        ctx.set_alpn_protocols(['h2'])
    else:
        ctx.set_alpn_protocols(['http/1.1'])
    return ctx

async def main():
    """cf-sim 메인: h1(8443) + h2(8444) 서버 시작."""
    h1_ctx = make_ssl_ctx('h1')
    h2_ctx = make_ssl_ctx('h2')
    # Run two listeners: one for h1 (port 8443), one for h2 (port 8444)
    server_h1 = await asyncio.start_server(lambda r, w: handle_http1_wrap(r, w), '127.0.0.1', PORT, ssl=h1_ctx)
    PORT_H2 = PORT + 1
    server_h2 = await asyncio.start_server(lambda r, w: handle_h2_wrap(r, w), '127.0.0.1', PORT_H2, ssl=h2_ctx)
    print(f'cf-sim h1 listening on {PORT}, h2 listening on {PORT_H2}', flush=True)
    async with server_h1, server_h2:
        await asyncio.gather(server_h1.serve_forever(), server_h2.serve_forever())

async def handle_http1_wrap(reader, writer):
    """HTTP/1.1 래퍼 (에러 처리)."""
    peer = writer.get_extra_info('peername')
    m.active += 1
    m.peak_concurrent = max(m.peak_concurrent, m.active)
    try:
        await handle_http1(reader, writer, peer)
    except Exception:
        pass
    finally:
        m.active -= 1
        try:
            writer.close(); await writer.wait_closed()
        except Exception:
            pass

async def handle_h2_wrap(reader, writer):
    """H2 래퍼 (에러 처리)."""
    peer = writer.get_extra_info('peername')
    await handle_h2(reader, writer, peer)

if __name__ == '__main__':
    asyncio.run(main())
