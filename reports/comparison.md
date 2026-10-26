# dossal vs commercial tools

This document compares dossal's features against well-known commercial/ open-source DoS tools. It is a qualitative comparison, not benchmark evidence.

| Feature | dossal | h3c | h3c++ | golden | k6 | locust | wrk |
|---|---:|---:|---:|---:|---:|---:|---:|
| Local-only mode | yes | no | no | no | yes | yes | yes |
| WebSocket | yes | no | no | no | yes | no | no |
| TCP raw | yes | no | no | no | yes | yes | no |
| HTTP keep-alive | yes | yes | yes | yes | yes | yes | yes |
| HTTPS/TLS | via proxy | yes | yes | yes | yes | yes | yes |
| Async nonblocking | yes | yes | yes | yes | yes | yes | yes |
| Easy CLI | yes | no | no | no | yes | yes | yes |
| JSON stats | yes | yes | yes | yes | yes | yes | yes |

The claim: dossal is not "better" in every dimension; it is intentionally **lighter, faster to deploy, and more flexible for local target validation** than heavyweight commercial tools. It can be extended to TLS, UDP, SYN, and HTTP/2 without changing the core architecture.
