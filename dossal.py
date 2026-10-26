#!/usr/bin/env python3
"""
dossal v0.2 — comprehensive DoS stress engine
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

class Stats:
    def __init__(self):
        self.requests=0; self.bytes=0; self.errors=0; self.opens=0; self.ws_msgs=0
    def rps(self, dur): return self.requests/dur if dur else 0
    def bps(self, dur): return self.bytes/dur if dur else 0
    def report(self, mode,url,conns,dur):
        return {
          "tool":"dossal","version":"0.2","mode":mode,"url":url,"connections":conns,"duration_s":dur,
          "requests":self.requests,"rps":round(self.rps(dur),2),
          "bytes":self.bytes,"bps":round(self.bps(dur),2),
          "errors":self.errors
        }

async def http_worker(name,url,stats,duration,stop):
    p = urlparse(url)
    host, port, path = p.hostname, p.port or 80, p.path or '/'
    reader, writer = await asyncio.open_connection(host, port)
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
           f"User-Agent: dossal/0.2\r\n\r\n")
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
    try: writer.close(); await writer.wait_closed()
    except: pass

async def https_worker(name,url,stats,duration,stop):
    p = urlparse(url)
    host, port, path = p.hostname, p.port or 443, p.path or '/'
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
           f"User-Agent: dossal/0.2\r\n\r\n")
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
    try: writer.close(); await writer.wait_closed()
    except: pass

async def ws_worker(name,url,stats,duration,stop):
    host, port, path = parse_ws(url)
    reader, writer = await asyncio.open_connection(host, port)
    key = base64.b64encode(random.randbytes(16)).decode()
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
    writer.write(req.encode()); await writer.drain()
    handshake = await asyncio.wait_for(reader.read(8192), timeout=1.0)
    if b"101" not in handshake:
        stats.errors += 1; writer.close(); return
    payload = b"x" * 128
    while not stop.is_set():
        try:
            mask = random.randbytes(4)
            masked = bytes(b ^ mask[i%4] for i,b in enumerate(payload))
            header = struct.pack("!B", 0x81)
            if len(payload)<126: header += struct.pack("!B", 0x80 | len(payload))
            else: header += struct.pack("!BH", 0x80|126, len(payload))
            header += mask
            writer.write(header + masked); await writer.drain()
            stats.ws_msgs += 1; stats.bytes += len(payload)
            await asyncio.sleep(0.001)
        except Exception:
            stats.errors += 1; break
    try: writer.close(); await writer.wait_closed()
    except: pass

async def tcp_worker(name,url,stats,duration,stop):
    host, port = parse_tcp(url)
    reader, writer = await asyncio.open_connection(host, port)
    payload = b"A" * 1024
    while not stop.is_set():
        try:
            writer.write(payload); await writer.drain()
            stats.bytes += len(payload)
            await asyncio.sleep(0.001)
        except Exception:
            stats.errors += 1; break
    try: writer.close(); await writer.wait_closed()
    except: pass

async def udp_worker(name,url,stats,duration,stop,payload_size=512):
    host, port = parse_udp(url)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"B" * payload_size
    loop = asyncio.get_event_loop()
    while not stop.is_set():
        try:
            loop.run_in_executor(None, sock.sendto, (payload, (host, port)))
            stats.bytes += payload_size
            await asyncio.sleep(0.001)
        except Exception:
            stats.errors += 1
            break
    sock.close()

def parse_ws(u):
    p = urlparse(u); return p.hostname, p.port or 80, p.path or "/"
def parse_tcp(u):
    p = urlparse(u); return p.hostname, int(p.port)
def parse_udp(u):
    p = urlparse(u); return p.hostname, int(p.port)

async def run(mode, url, conns, duration, stats):
    stop = asyncio.Event()
    async def finish():
        await asyncio.sleep(duration); stop.set()
    task = asyncio.create_task(finish())
    workers = []
    for i in range(conns):
        if mode=="http": workers.append(asyncio.create_task(http_worker(i,url,stats,duration,stop)))
        elif mode=="https": workers.append(asyncio.create_task(https_worker(i,url,stats,duration,stop)))
        elif mode=="websocket": workers.append(asyncio.create_task(ws_worker(i,url,stats,duration,stop)))
        elif mode=="tcp": workers.append(asyncio.create_task(tcp_worker(i,url,stats,duration,stop)))
        elif mode=="udp": workers.append(asyncio.create_task(udp_worker(i,url,stats,duration,stop)))
    await asyncio.gather(*workers, return_exceptions=True)
    stop.set(); await task
    return stats

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="http", choices=["http","https","websocket","tcp","udp"])
    ap.add_argument("--url", required=True)
    ap.add_argument("--connections", type=int, default=100)
    ap.add_argument("--duration", type=int, default=10)
    args = ap.parse_args()
    stats = Stats()
    asyncio.run(run(args.mode, args.url, args.connections, args.duration, stats))
    print(json.dumps(stats.report(args.mode, args.url, args.connections, args.duration), indent=2))

if __name__ == "__main__":
    main()
