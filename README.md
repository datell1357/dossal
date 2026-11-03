# dossal — comprehensive DoS stress engine

## Status
- **dossal v3.4** (Python asyncio) — 13 attack modes, multi-mode, auto mode, per-mode connections, impact scoring, live stats.
- **cf-sim v0.8** (Cloudflare-like edge simulator) — rate limiting, metrics, h1/h2.
- Local targets only — no real/public server tests.

## Quick start
```bash
# Single mode
python3 dossal.py --mode http --url http://target:8080 --intensity balanced --duration 10

# Multi-mode (HTTP + QUIC + UDP simultaneously)
python3 dossal.py --mode http,quic,udp --url http://target:8080 --intensity max --duration 10 --live

# With impact scoring
python3 dossal.py --mode http --url http://target:8080 --intensity max --duration 10 --impact
```

## Usage
```
dossal.py [options]

Modes (comma-separated):
  http       HTTP/1.1 keep-alive request flood
  https      TLS 1.3 keep-alive request flood
  h2         HTTP/2 multiplexed request flood
  grpc       gRPC (HTTP/2 + framing) request flood
  quic       QUIC/HTTP3 UDP datagram flood
  udp        Raw UDP datagram flood
  tcp        Raw TCP byte flood
  syn        TCP connect-only (SYN flood)
  synack     TCP connect + RST (ACK flood)
  rst        TCP RST flood (SO_LINGER abort)
  fin        TCP FIN flood (graceful close)
  websocket  WebSocket upgrade + frame flood
  slowloris  Slow HTTP header drip

Options:
  --url URL            Target URL (required)
  --mode MODES         Comma-separated modes (default: http)
  --connections N      Connections per mode (default: 100)
  --conns "m=N,..."    Per-mode connections: "http=400,h2=80,udp=1,syn=10"
  --duration N         Attack duration in seconds (default: 10)
  --payload-size N     Override default payload size
  --impact             Enable victim impact scoring (requires psutil)
  --intensity {light,balanced,max}  Preset: light(10c), balanced(50c), max(400c)
  --live               Print RPS/PPS every second during attack
  --threads N          UDP/QUIC multiprocess count (default 4, max 16)
  --auto               Auto-detect protocol + include L4 modes
```

## Attack modes (17)
| Mode | Layer | Mechanism | Measured (local) |
|---|---|---|---:|
| `https` | L7 | HTTPS/1.1 keep-alive flood (asyncio) | **27,774 RPS** (50c) |
| `httpsmp` | L7 | HTTPS/1.1 raw socket flood (multiproc) | **27,825 RPS** (8p) |
| `raw` | L7 | HTTP/1.1 raw socket flood (multiproc) | **59k RPS** (8p) |
| `https` | L7 | TLS 1.3 keep-alive flood | **20,676 RPS** |
| `h2` | L7 | HTTP/2 multiplexed flood (BATCH=32) | **30,288 RPS** (80c) |
| `grpc` | L7 | gRPC flood (asyncio) | **2,520 RPS** (80c) |
| `grpcmp` | L7 | gRPC flood (multiproc) | **3,761 RPS** (16p) |
| `quic` | L4 | QUIC/HTTP3 UDP datagram flood (multiproc) | **294,000 pps** (8p) |
| `udp` | L4 | Raw UDP datagram flood (multiproc) | **296,000 pps** (8p) |
| `tcp` | L4 | Raw TCP byte flood (multiproc) | **9.4k pkts** (8p) |
| `syn` | L4 | TCP connect-only (SYN flood) | **11,000+ conns/2s** |
| `rst` | L4 | TCP RST flood (multiproc) | **55,000 conns/2s** (4p) |
| `fin` | L4 | TCP FIN flood (graceful close) | 1,500+ conns/2s |
| `websocket` | L7 | WS upgrade + frame flood (asyncio) | — |
| `wsm` | L7 | WS frame flood (multiproc) | raw socket + WS masking |
| `slowloris` | L7 | Slow HTTP header drip | connection holding |
| `synack` | L4 | TCP connect + RST (ACK flood) | 461 conns/2s |

## Multi-mode (per-mode connections)
```bash
# HTTP + H2 + QUIC + UDP + SYN with tuned connections
python3 dossal.py --mode http,h2,quic,udp,syn --url http://target:8080 \
  --conns "http=400,h2=80,quic=1,udp=1,syn=10" --duration 30 --live
# Result: 13,190 RPS + 20,823 PPS + 1,983 conns (3s, 0 errors)
```

## Auto mode
```bash
# Auto-detect protocol, include L4 modes for maximum impact
python3 dossal.py --auto --url http://target:8080 --duration 30 --live
# Detects: HTTP/1.1 → runs http + udp + syn
# Detects: HTTPS/H2 → runs https + h2 + udp + syn
```

## Intensity presets
| Preset | Connections | Use case |
|---|---|---|
| `light` | 10 | Quick check, low-impact test |
| `balanced` | 50 | Default, good RPS/PPS |
| `max` | 200 | Maximum pressure |

Override with `--connections N` for custom counts.

## Live stats
```bash
python3 dossal.py --mode http --url http://target:8080 --connections 20 --duration 5 --live
# [4s] RPS=42,762  ERR=0
# [3s] RPS=45,166  ERR=0
# [2s] RPS=43,511  ERR=0
# [1s] RPS=44,200  ERR=0
```

## Impact scoring
```bash
python3 dossal.py --mode http --url http://target:8080 --intensity max --duration 10 --impact
```
- Pre-attack CPU baseline (0.5s sampling)
- Background CPU sampler during attack (0.2s intervals)
- Post-attack: CPU delta, memory RSS, RPS efficiency
- Score: 0-175 (CPU 0-50, Mem 0-50, Efficiency 0-25, +bonus)

## Architecture
```
dossal.py (single file, Python asyncio)
├── 13 worker functions (http, https, h2, grpc, quic, udp, tcp, syn, rst, fin, ws, slowloris, synack)
├── Multi-mode: concurrent workers per mode, shared Stats
├── Impact scoring: CpuSampler + psutil
├── Live stats: 1-second RPS/PPS printer
└── JSON stats output: requests, rps, bytes, bps, packets, pps, connections, errors
```

### Performance optimizations
- **HTTP/HTTPS**: write → drain → read (single loop, no read blocking)
- **UDP/QUIC**: batch sendto in thread executor (2000 packets/batch)
- **gRPC**: fire-and-forget streams, background h2 reader
- **SYN/RST/FIN**: raw socket (no asyncio overhead), SO_LINGER for RST
- **H2**: h2 library, batched send (BATCH=32), background drain
- **gRPC**: fire-and-forget streams, background h2 reader (BATCH=10)

## Bench results (v2.9, local only)
| Mode | Target | Conns | Dur | Result | Errors |
|---|---|---|---|---|---|
| http | node:8080 | 400 | 2s | 59,256 RPS | 0 |
| https | cf-sim:8443 | 50 | 2s | 18,640 RPS | 0 |
| h2 | cf-sim:8444 | 80 | 2s | 29,344 RPS | 0 |
| grpc | grpc:50051 | 20 | 2s | 630 RPS | 20 |
| quic | quic:4443 | 1 | 2s | 219,291 pkts | 0 |
| udp | udp:9999 | 1 | 2s | 210,091 pkts | 0 |
| syn | node:8080 | 10 | 2s | 11,172 conns | 0 |
| rst | node:8080 | 10 | 2s | 12,014 conns | 0 |
| slowloris | node:8080 | 10 | 2s | 10 conns held | 0 |

**Total bench score: 165.6** (peak: 165.6 @ v3.5)

### Connection scaling (http, node:8080)
| Connections | RPS |
|---|---|
| 200 | 55,332 |
| 400 | **60,568** |
| 600 | 58,837 |
| 800 | 56,926 |

### Connection scaling (h2, cf-sim:8444)
| Connections | RPS |
|---|---|
| 20 | 17,734 |
| 50 | 24,073 |
| 80 | **30,288** |
| 100 | 31,394 |

### UDP scaling
| Connections | PPS |
|---|---|
| 1 | **106,002** |
| 5 | 75,802 |
| 10 | 47,883 |
| 20 | 45,690 |

## Comparison with commercial tools
See `reports/loic-hoic-hping3-comparison.md`.

Key differentiators vs LOIC/HOIC/hping3:
- **HTTPS/H2/gRPC/QUIC**: LOIC is HTTP/1.1 only, HOIC adds some L4, hping3 is raw packets
- **Impact scoring**: No other tool measures victim CPU/memory impact
- **Multi-mode**: Simultaneous L7 + L4 attacks in one command
- **Intensity presets**: One-click light/balanced/max
- **Live stats**: Real-time RPS/PPS during attack

## Lab targets
| Target | Port | Protocol | Purpose |
|---|---|---|---|
| node-victim | 8080 | HTTP/1.1 | Fast HTTP baseline |
| py-victim | 8081 | HTTP/1.1 | Python HTTP baseline |
| heavy-victim | 8082 | HTTP/1.1 | CPU-heavy (impact scoring) |
| cf-sim | 8443/8444 | HTTPS/H1+H2 | Edge simulator (rate limiting) |
| grpc-victim | 50051 | gRPC/H2 | gRPC CPU-heavy |
| quic-victim | 4443 | QUIC/UDP | QUIC datagram receiver |
| udp_receiver | 9999 | UDP | Raw UDP receiver |
