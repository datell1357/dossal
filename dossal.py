#!/usr/bin/env python3
"""
dossal v0.3 — comprehensive DoS stress engine
Modes:
  http      : HTTP/1.1 keep-alive request flood (plain)
  https     : TLS request flood (HTTP/1.1, self-signed cert)
  websocket : WebSocket upgrade flood
  tcp       : raw TCP byte flood
  udp       : raw UDP datagram flood
Targets are local only. JSON stats output.
"""
import asyncio, ssl, socket, json, math, struct, random, time, argparse, signal, sys, base64
from urllib.parse import urlparse
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived

class Stats:
    def __init__(self):
        self.requests=0; self.bytes=0; self.errors=0; self.opens=0; self.ws_msgs=0
    def rps(self, dur): return self.requests/dur if dur else 0
    def bps(self, dur): return self.bytes/dur if dur else 0
    def report(self, mode,url,conns,dur):
        return {
          "tool":"dossal","version":"0.3","mode":mode,"url":url,"connections":conns,"duration_s":dur,
          "requests":self.requests,"rps":round(self.rps(dur),2),
          "bytes":self.bytes,"bps":round(self.bps(dur),2),
          "errors":self.errors
        }

def parse_http(u):
    p = urlparse(u)
    return p.hostname, p.port or (443 if p.scheme == "https" else 80), p.path or "/"

def parse_ws(u):
    p = urlparse(u)
    return p.hostname, p.port or 80, p.path or "/"

def parse_tcp(u):
    p = urlparse(u)
    return p.hostname, int(p.port)

def parse_udp(u):
    p = urlparse(u)
    return p.hostname, int(p.port)

async def http_worker(name, url, stats, duration, stop, payload_size=0):
    host, port, path = parse_http(url)
    reader, writer = await asyncio.open_connection(host, port)
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
           f"User-Agent: dossal/0.3\r\n\r\n")
    while not stop.is_set():
        try:
            writer.write(req.encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(8192), timeout=1.0)
            stats.requests += 1
            stats.bytes += len(resp)
        except Exception:
            stats.errors += 1
            break
    try:
        writer.close(); await writer.wait_closed()
    except Exception:
        pass

async def https_worker(name, url, stats, duration, stop, payload_size=0):
    host, port, path = parse_http(url)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
           f"User-Agent: dossal/0.3\r\n\r\n")
    while not stop.is_set():
        try:
            writer.write(req.encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(8192), timeout=1.0)
            stats.requests += 1
            stats.bytes += len(resp)
        except Exception:
            stats.errors += 1
            break
    try:
        writer.close(); await writer.wait_closed()
    except Exception:
        pass

async def ws_worker(name, url, stats, duration, stop, payload_size=128):
    host, port, path = parse_ws(url)
    reader, writer = await asyncio.open_connection(host, port)
    key = base64.b64encode(random.randbytes(16)).decode()
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
    writer.write(req.encode()); await writer.drain()
    handshake = await asyncio.wait_for(reader.read(8192), timeout=1.0)
    if b"101" not in handshake:
        stats.errors += 1
        writer.close(); return
    payload = b"x" * payload_size
    while not stop.is_set():
        try:
            mask = random.randbytes(4)
            masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            header = struct.pack("!B", 0x81)
            if len(payload) < 126:
                header += struct.pack("!B", 0x80 | len(payload))
            else:
                header += struct.pack("!BH", 0x80 | 126, len(payload))
            header += mask
            writer.write(header + masked); await writer.drain()
            stats.ws_msgs += 1
            stats.bytes += len(payload)
        except Exception:
            stats.errors += 1
            break
    try:
        writer.close(); await writer.wait_closed()
    except Exception:
        pass

async def tcp_worker(name, url, stats, duration, stop, payload_size=1024):
    host, port = parse_tcp(url)
    reader, writer = await asyncio.open_connection(host, port)
    payload = b"A" * payload_size
    while not stop.is_set():
        try:
            writer.write(payload); await writer.drain()
            stats.bytes += len(payload)
        except Exception:
            stats.errors += 1
            break
    try:
        writer.close(); await writer.wait_closed()
    except Exception:
        pass

async def udp_worker(name, url, stats, duration, stop, payload_size=1400):
    host, port = parse_udp(url)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"B" * payload_size
    loop = asyncio.get_event_loop()
    pending = 0
    max_pending = 10000
    while not stop.is_set():
        try:
            if pending >= max_pending:
                await asyncio.sleep(0.001)
                continue
            pending += 1
            loop.run_in_executor(None, sock.sendto, (payload, (host, port)))
            stats.bytes += payload_size
        except Exception:
            stats.errors += 1
            break
    sock.close()

async def h2_worker(name, url, stats, duration, stop, payload_size=1024):
    host, port, path = parse_http(url)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    writer.write(conn.data_to_send())
    await writer.drain()
    headers = [
        (':method', 'GET'),
        (':scheme', 'https'),
        (':authority', host),
        (':path', path),
        ('user-agent', 'dossal/0.3'),
    ]
    while not stop.is_set():
        try:
            stream_id = conn.get_next_available_stream_id()
            conn.send_headers(stream_id, headers)
            data = conn.data_to_send()
            if data:
                writer.write(data); await writer.drain()
            # Read response
            resp = await asyncio.wait_for(reader.read(8192), timeout=1.0)
            events = conn.receive_data(resp)
            for event in events:
                if isinstance(event, ResponseReceived):
                    stats.requests += 1
                    stats.bytes += len(resp)
        except Exception:
            stats.errors += 1
            break
    try:
        writer.close(); await writer.wait_closed()
    except Exception:
        pass

async def run(mode, url, conns, duration, stats, payload_size):
    stop = asyncio.Event()
    async def finish():
        await asyncio.sleep(duration); stop.set()
    task = asyncio.create_task(finish())
    workers = []
    for i in range(conns):
        if mode == "http":
            workers.append(asyncio.create_task(http_worker(i, url, stats, duration, stop, payload_size)))
        elif mode == "https":
            workers.append(asyncio.create_task(https_worker(i, url, stats, duration, stop, payload_size)))
        elif mode == "websocket":
            workers.append(asyncio.create_task(ws_worker(i, url, stats, duration, stop, payload_size)))
        elif mode == "tcp":
            workers.append(asyncio.create_task(tcp_worker(i, url, stats, duration, stop, payload_size)))
        elif mode == "udp":
            workers.append(asyncio.create_task(udp_worker(i, url, stats, duration, stop, payload_size)))
        elif mode == "h2":
            workers.append(asyncio.create_task(h2_worker(i, url, stats, duration, stop, payload_size)))
    await asyncio.gather(*workers, return_exceptions=True)
    stop.set()
    await task
    return stats

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="http", choices=["http","https","websocket","tcp","udp","h2"])
    ap.add_argument("--url", required=True)
    ap.add_argument("--connections", type=int, default=100)
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--payload-size", type=int, default=None,
                    help="Override default payload size per mode")
    args = ap.parse_args()
    stats = Stats()
    # choose default payload size by mode
    if args.payload_size is None:
        defaults = {"http": 0, "https": 0, "websocket": 128, "tcp": 1024, "udp": 1400, "h2": 1024}
        payload_size = defaults[args.mode]
    else:
        payload_size = args.payload_size
    asyncio.run(run(args.mode, args.url, args.connections, args.duration, stats, payload_size))
    print(json.dumps(stats.report(args.mode, args.url, args.connections, args.duration), indent=2))

if __name__ == "__main__":
    main()
