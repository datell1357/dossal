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
| node-victim:8080 | http | 20 | 5s | 60,362 | 12,072 | 46.0 MB | 13 | split reader/writer |
| node-victim:8080 | http | 20 | 5s | 606,270 | 121,254 | 86.7 MB | 0 | old single-loop |
| cf-sim:8443 | https | 20 | 5s | 95,748 | 19,150 | 15.0 MB | 3 | rate limited by cf-sim |
| cf-sim:8444 | h2 | 10 | 5s | 47,850 | 9,570 | 1.6 MB | 0 | h2 fixed |
| cf-sim:8444 | h2 | 20 | 10s | 105,524 | 10,552 | 3.5 MB | 0 | h2 stable |
| cf-sim:8444 | h2 | 50 | 10s | 113,806 | 11,381 | 3.8 MB | 0 | h2 scaled |

cf-sim h1 edge metrics (cumulative):
```json
{"requests": 169847, "received_bytes": 11581287, "sent_bytes": 1845024, "limited": 15091303, "peak_concurrent": 20, "per_ip_buckets": 216}
```

## Key fixes in v0.4
- **H2 mode**: proper handshake (wait for server SETTINGS before sending requests), ALPN negotiation, TCP_NODELAY
- **HTTPS mode**: split reader/writer loops to avoid SSL shutdown deadlock, force-close transport
- **HTTP/1.1**: proper Content-Length based response reading (no more partial reads)
- **cf-sim**: separate h1/h2 listeners with ALPN, proper h2 SETTINGS handshake

## Tool vs commercial tools
See `reports/comparison.md` for a qualitative comparison. dossal's differentiator: single-file, local-first, WebSocket + TCP + HTTPS + UDP + HTTP/2 in one CLI, JSON output, and easy extension to SYN.

## Next steps
1. Add SYN/ACK mode using raw sockets (requires privileged port).
2. Optimize http_worker performance (split reader/writer slower than single-loop for plain HTTP).
3. Add per-victim CPU/memory sampling to produce an impact score.
4. Build a CLI dashboard to run all modes in parallel with live metrics.
5. Add connection-limit handling and reconnection logic.
6. Create a `--target-impact` mode that reports victim health before/after.
