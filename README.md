# dossal — comprehensive DoS lab

## Status
- dossal v0.5 (Python asyncio) with http, https, websocket, tcp, udp, h2 modes.
- cf-sim v0.8 (Cloudflare-like edge simulator) with rate limiting, metrics, h1/h2.
- Local targets only — no real/public server tests.
  - node-victim on port 8080 (HTTP/1.1, Node.js)
  - py-victim on port 8081 (HTTP/1.1, Python)
  - cf-sim on port 8443 (HTTP/1.1 TLS) and 8444 (HTTP/2)

## Test results (local only, v0.5)
| Target | Mode | Conns | Dur | Requests | RPS | MB | Errors |
|---|---|---:|---:|---:|---:|---:|---:|
| node-victim:8080 | http | 20 | 5s | 259,284 | 51,857 | 37.1 | 0 |
| cf-sim:8443 | https | 20 | 5s | 113,278 | 22,656 | 56.3 | 19 |
| cf-sim:8444 | h2 | 50 | 10s | 131,676 | 13,168 | 4.3 | 0 |

cf-sim edge metrics (cumulative, after all tests):
```json
{"requests": 140631, "limited": 1653353, "peak_concurrent": 50, "per_ip_buckets": 21}
```
- 1.65M requests rate-limited (429) by cf-sim token bucket → Cloudflare-like shedding confirmed.
- h2: 131k requests processed, 0 errors → stable multiplexed load.

## v0.5 changes
- **http/https workers**: reverted to single-loop (write → read → repeat, no drain) for max throughput.
- **h2 worker**: removed debug prints; kept explicit server-SETTINGS wait before first request.
- **cf-sim**: removed per-event debug prints (was a major h2 throughput bottleneck); 429 responses have no Content-Length/body.

## Tool vs commercial tools
See `reports/comparison.md`. dossal: single-file, local-first, 6 protocol modes, JSON output, extensible.

## Next
1. SYN/ACK mode (raw sockets, `--mode syn`)
2. Victim impact score (CPU/memory sampling)
3. Multi-mode parallel dashboard
4. gRPC/QUIC modes
5. Connection-pool reconnection logic
