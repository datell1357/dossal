# dossal — comprehensive DoS lab

## Status
- dossal v0.4 (Python asyncio) implemented with http, https, websocket, tcp, udp, h2 modes.
- Local targets:
  - node-victim on port 8080 (HTTP/1.1)
  - py-victim on port 8081 (HTTP/1.1, single-threaded)
  - cf-sim on port 8443 (HTTP/1.1 TLS edge simulator) and 8444 (HTTP/2 edge simulator)
- No real/public server tests performed.

## Test results (local only)
| Target | Mode | Connections | Duration | Requests | RPS | Bytes | Errors | Notes |
|---|---|---:|---:|---:|---:|---:|---:|---|
| node-victim:8080 | http | 10 | 5s | 334,656 | 66,931 | 47.8 MB | 0 | fast victim |
| node-victim:8080 | http | 100 | 10s | 751,910 | 75,191 | 107.5 MB | 0 | fast victim |
| py-victim:8081 | http | 10 | 5s | 12 | 2.4 | 558 B | 6 | victim bottleneck |
| py-victim:8081 | tcp | 10 | 5s | 0 | 0 | 405 KB | 6 | raw TCP |
| cf-sim:8443 | https | 10 | 5s | 64,742 | 12,948 | 25.0 MB | 0 | edge simulator |
| cf-sim:8444 | h2 | 10 | 5s | 10 | 2.0 | 510 B | 10 | h2 handshake verified; throughput low due to h2 framing read loop |

cf-sim h1 edge metrics after https flood:
```json
{"requests": 47163, "received_bytes": 754590, "sent_bytes": 424590, "limited": 951255, "peak_concurrent": 10, "active": 1, "started": 1793023519.095364, "now": 1793023727.5155861}
```

cf-sim h1 edge metrics after h2 test (h2 requests appear in h1 metrics because h2 listener also calls m.requests):
```json
{"requests": 25, "received_bytes": 2062, "sent_bytes": 429, "limited": 0, "peak_concurrent": 10, "active": 1, "started": 1793038734.408637, "now": 1793039499.707138, "per_ip_buckets": 3}
```

## Tool vs commercial tools
See `reports/comparison.md` for a qualitative comparison. dossal's differentiator: single-file, local-first, WebSocket + TCP + HTTPS + UDP + HTTP/2 in one CLI, JSON output, and easy extension to SYN.

## Next steps
1. Add SYN/ACK mode using raw sockets (requires privileged port).
2. Tune h2 throughput (use non-blocking h2 reads or a dedicated read loop).
3. Add per-victim CPU/memory sampling to produce an impact score.
4. Build a CLI dashboard to run all modes in parallel with live metrics.
5. Add connection-limit handling and reconnection logic.
6. Create a `--target-impact` mode that reports victim health before/after.
