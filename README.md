# dossal — comprehensive DoS lab

## Status
- **dossal v0.6** (Python asyncio) — 11 attack modes, multi-mode, impact scoring.
- **cf-sim v0.8** (Cloudflare-like edge simulator) — rate limiting, metrics, h1/h2.
- Local targets only — no real/public server tests.
  - node-victim on port 8080 (HTTP/1.1, Node.js)
  - py-victim on port 8081 (HTTP/1.1, Python)
  - cf-sim on port 8443 (HTTP/1.1 TLS) and 8444 (HTTP/2)
  - udp_receiver on port 9999 (UDP)

## Attack modes (11)
| Mode | Layer | Mechanism | RPS (20c, 5s) |
|---|---|---|---:|
| `http` | L7 | HTTP/1.1 keep-alive flood | **50,137** |
| `https` | L7 | TLS 1.3 keep-alive flood | **20,965** |
| `h2` | L7 | HTTP/2 multiplexed flood | **13,180** |
| `udp` | L4 | UDP datagram flood | **200,000 pps** |
| `tcp` | L4 | Raw TCP byte flood | 705 pkts (backpressure) |
| `syn` | L4 | TCP connect-only (SYN flood) | **16,083 conns** |
| `rst` | L4 | TCP RST flood (abort) | **61,677 conns** |
| `fin` | L4 | TCP FIN flood (graceful close) | **16,088 conns** |
| `websocket` | L7 | WS upgrade + frame flood | — |
| `slowloris` | L7 | Slow HTTP header drip | **10 conns held** |
| `synack` | L4 | TCP connect + RST (ACK flood) | — |

## Multi-mode
```bash
dossal.py --mode http,h2,udp --url http://target:8080 --connections 10
```
Runs all three modes simultaneously, aggregates stats.

## Impact scoring
```bash
dossal.py --mode http --url http://target:8080 --connections 20 --duration 5 --impact
```
Samples victim CPU/memory via psutil, computes impact score (0-175).

## Test results (v0.6, local only)
| Target | Mode | Conns | Dur | RPS/Pkts | Errors |
|---|---|---:|---:|---:|---:|
| node-victim:8080 | http | 20 | 5s | 50,137 RPS | 0 |
| cf-sim:8443 | https | 20 | 5s | 20,965 RPS | 19 (429) |
| cf-sim:8444 | h2 | 50 | 10s | 13,180 RPS | 0 |
| udp:9999 | udp | 20 | 5s | 200,000 pps | 0 |
| node-victim:8080 | syn | 20 | 5s | 16,083 conns | 16,868 |
| node-victim:8080 | rst | 20 | 5s | 61,677 conns | 0 |
| node-victim:8080 | fin | 20 | 5s | 16,088 conns | 22,135 |
| node-victim:8080 | slowloris | 10 | 5s | 10 conns held | 0 |

## vs LOIC / HOIC / hping3
See `reports/loic-hoic-hping3-comparison.md`.

| Tool | HTTP L7 | HTTPS | H2 | SYN/ACK | WS | Impact |
|---|---|---|---|---|---|---|
| LOIC | ~10-30k | ❌ | ❌ | △ | ❌ | ❌ |
| HOIC | ~20-50k | ❌ | ❌ | △ | ❌ | ❌ |
| hping3 | — | — | — | ✅ 100k-1M pps | ❌ | ❌ |
| **dossal v0.6** | **50k** | **21k** | **13k** | **16k-62k conns** | ✅ | ✅ |

## Next
1. Raw socket SYN/ACK (macOS: `setsockopt(SO_LINGER, 0)`)
2. gRPC streaming mode
3. QUIC/HTTP3 mode
4. Multi-process (multiprocessing) for true parallelism
