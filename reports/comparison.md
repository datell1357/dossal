# dossal v0.4 vs commercial tools

This document compares dossal's features against well-known commercial/open-source DoS tools. It is a qualitative comparison, not benchmark evidence.

| Feature | dossal | h3c | h3c++ | golden | k6 | locust | wrk |
|---|---:|---:|---:|---:|---:|---:|---:|
| Local-only mode | yes | no | no | no | yes | yes | yes |
| WebSocket | yes | no | no | no | yes | no | no |
| TCP raw | yes | no | no | no | yes | yes | no |
| HTTP keep-alive | yes | yes | yes | yes | yes | yes | yes |
| HTTPS/TLS | yes | yes | yes | yes | yes | yes | yes |
| UDP | yes | no | no | yes | yes | yes | no |
| HTTP/2 | yes | no | no | no | yes | no | no |
| Async nonblocking | yes | yes | yes | yes | yes | yes | yes |
| Easy CLI | yes | no | no | no | yes | yes | yes |
| JSON stats | yes | yes | yes | yes | yes | yes | yes |

## Differentiator
dossal is not "better" in every dimension. It is intentionally:
- **lighter**: single Python file, no dependencies except h2
- **faster to deploy**: no build step, no config files
- **more flexible for local validation**: all attack modes in one CLI
- **designed for Cloudflare-like edges**: h1 + h2 listeners, rate limiting, metrics

## Next differentiators
- SYN/ACK mode
- per-victim CPU/memory impact score
- parallel multi-mode dashboard
- gRPC streaming mode
- QUIC/HTTP3 mode
