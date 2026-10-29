# dossal — comprehensive DoS lab

## Status
- **dossal v0.8** (Python asyncio) — 13 attack modes, multi-mode, impact scoring.
- **cf-sim v0.8** (Cloudflare-like edge simulator) — rate limiting, metrics, h1/h2.
- Local targets only — no real/public server tests.
  - node-victim on port 8080 (HTTP/1.1, Node.js)
  - py-victim on port 8081 (HTTP/1.1, Python)
  - cf-sim on port 8443 (HTTP/1.1 TLS) and 8444 (HTTP/2)
  - grpc-victim on port 50051 (gRPC/HTTP2)
  - quic-victim on port 4443 (QUIC/UDP)
  - udp_receiver on port 9999 (UDP)

## Attack modes (13)
| Mode | Layer | Mechanism | Measured (local) |
|---|---|---|---:|
| `http` | L7 | HTTP/1.1 keep-alive flood | **47,739 RPS** |
| `https` | L7 | TLS 1.3 keep-alive flood | **22,215 RPS** |
| `h2` | L7 | HTTP/2 multiplexed flood | **11,563 RPS** |
| `grpc` | L7 | gRPC (HTTP/2 + framing) flood | 105 RPS (CPU-heavy victim) |
| `quic` | L4 | QUIC/HTTP3 UDP datagram flood | **200,000 pps** |
| `udp` | L4 | Raw UDP datagram flood | **100,000 pps** |
| `tcp` | L4 | Raw TCP byte flood | 597 pkts (backpressure) |
| `syn` | L4 | TCP connect-only (SYN flood) | **16,127 conns** |
| `rst` | L4 | TCP RST flood (abort) | **6,306 conns** |
| `fin` | L4 | TCP FIN flood (graceful close) | 30 conns |
| `websocket` | L7 | WS upgrade + frame flood | — |
| `slowloris` | L7 | Slow HTTP header drip | 5 conns held |
| `synack` | L4 | TCP connect + RST (ACK flood) | 3 conns |

## Multi-mode
```bash
dossal.py --mode http,grpc,quic,udp --url http://target:8080 --connections 5
```
Runs all four modes simultaneously. Measured: **866 RPS + 150,000 pps** in 5s.

## Impact scoring
```bash
dossal.py --mode http --url http://target:8080 --connections 20 --duration 5 --impact
```
Samples victim CPU/memory via psutil, computes impact score (0-175).

## Test results (v0.8, local only)
| Target | Mode | Conns | Dur | RPS/Pkts | Errors |
|---|---|---:|---:|---:|---:|
| node-victim:8080 | http | 20 | 5s | 47,739 RPS | 0 |
| cf-sim:8443 | https | 20 | 5s | 22,215 RPS | 19 (429) |
| cf-sim:8444 | h2 | 20 | 5s | 11,563 RPS | 0 |
| grpc-victim:50051 | grpc | 5 | 3s | 105 RPS | 5 |
| quic-victim:4443 | quic | 10 | 5s | 200,000 pps | 0 |
| udp:9999 | udp | 10 | 5s | 100,000 pps | 0 |
| node-victim:8080 | syn | 5 | 3s | 16,127 conns | 8,585 |
| node-victim:8080 | rst | 5 | 3s | 6,306 conns | 4,727 |
| node-victim:8080 | fin | 5 | 3s | 30 conns | 12,011 |
| node-victim:8080 | slowloris | 5 | 3s | 5 conns held | 0 |

## vs LOIC / HOIC / hping3
See `reports/loic-hoic-hping3-comparison.md`.

| Tool | HTTP | HTTPS | H2 | gRPC | QUIC | SYN/ACK | WS | Impact |
|---|---|---|---|---|---|---|---|---|
| LOIC | ~10-30k | ❌ | ❌ | ❌ | ❌ | △ | ❌ | ❌ |
| HOIC | ~20-50k | ❌ | ❌ | ❌ | ❌ | △ | ❌ | ❌ |
| hping3 | — | — | — | ❌ | ❌ | ✅ 100k-1M pps | ❌ | ❌ |
| **dossal v0.8** | **48k** | **22k** | **12k** | ✅ | **200k pps** | **16k-6k conns** | ✅ | ✅ |

## Next
1. Raw socket SYN/ACK (macOS: `setsockopt(SO_LINGER, 0)`)
2. gRPC streaming (server-streaming, client-streaming)
3. Real QUIC handshake (aioquic)
4. Multi-process (multiprocessing) for true parallelism
5. Connection-pool reconnection logic
