# dossal — comprehensive DoS stress engine

## Status
- **dossal v2.0** (Python asyncio) — 13 attack modes, multi-mode, impact scoring, intensity presets, live stats.
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
  --duration N         Attack duration in seconds (default: 10)
  --payload-size N     Override default payload size
  --impact             Enable victim impact scoring (requires psutil)
  --intensity {light,balanced,max}  Preset: light(10c), balanced(50c), max(200c)
  --live               Print RPS/PPS every second during attack
  --threads N          Override connections for UDP/QUIC modes
  --payload-size N     Override default payload size
```

## Attack modes (13)
| Mode | Layer | Mechanism | Measured (local) |
|---|---|---|---:|
| `http` | L7 | HTTP/1.1 keep-alive flood | **60,742 RPS** (400c) |
| `https` | L7 | TLS 1.3 keep-alive flood | **20,676 RPS** |
| `h2` | L7 | HTTP/2 multiplexed flood | **13,120 RPS** (50c) |
| `grpc` | L7 | gRPC (HTTP/2 + framing) flood | **630 RPS** (20c, CPU-heavy) |
| `quic` | L4 | QUIC/HTTP3 UDP datagram flood | **106,000 pps** (1c) |
| `udp` | L4 | Raw UDP datagram flood | **106,000 pps** (1c) |
| `tcp` | L4 | Raw TCP byte flood | backpressure-limited |
| `syn` | L4 | TCP connect-only (SYN flood) | **11,000+ conns/2s** |
| `rst` | L4 | TCP RST flood (SO_LINGER abort) | **12,000+ conns/2s** |
| `fin` | L4 | TCP FIN flood (graceful close) | 1,500+ conns/2s |
| `websocket` | L7 | WS upgrade + frame flood | — |
| `slowloris` | L7 | Slow HTTP header drip | connection holding |
| `synack` | L4 | TCP connect + RST (ACK flood) | 461 conns/2s |

## Multi-mode
```bash
# HTTP + QUIC + UDP: 14k RPS + 23k PPS (20c, 2s)
python3 dossal.py --mode http,quic,udp --url http://target:8080 --connections 20 --duration 5 --live
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
- **H2**: h2 library, multiplexed streams per connection

## Bench results (v2.0, local only)
| Mode | Target | Conns | Dur | Result | Errors |
|---|---|---|---|---|---|
| http | node:8080 | 20 | 2s | 45,298 RPS | 0 |
| https | cf-sim:8443 | 20 | 2s | 19,646 RPS | 2 |
| h2 | cf-sim:8444 | 20 | 2s | 11,971 RPS | 0 |
| grpc | grpc:50051 | 5 | 2s | 158 RPS | 5 |
| quic | quic:4443 | 1 | 2s | 294,736 pkts | 0 |
| udp | udp:9999 | 1 | 2s | 210,278 pkts | 0 |
| syn | node:8080 | 10 | 2s | 10,532 conns | 0 |
| rst | node:8080 | 10 | 2s | 12,215 conns | 0 |
| slowloris | node:8080 | 10 | 2s | 10 conns held | 0 |

### Connection scaling (http, node:8080)
| Connections | RPS |
|---|---|
| 5 | 30,059 |
| 10 | 40,551 |
| 20 | 45,178 |
| 50 | 49,394 |
| 100 | 48,618 |
| 200 | 57,400 |
| 400 | **60,742** |

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
