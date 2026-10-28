# dossal v0.5 vs LOIC / HOIC / hping3

**수치는 전부 로컬 대상 (node-victim, py-victim, cf-sim)에서만 측정. 실전/공개 서버 테스트 없음.**
**단일 공격기 (single host), macOS 15, M-series, Python 3.14 asyncio.**

## 개요

| 도구 | 언어 | 타입 | 프로토콜 | 단일 호스트 L7 성능 |
|---|---|---|---|---|
| **LOIC** 0.89 | C (GTK GUI) | 단순 프러퍼 | HTTP GET/HEAD, TCP, UDP | 로컬 10k–30k RPS (기본 500 소켓) |
| **HOIC** | C# (boosters) | 단순 프러퍼 | HTTP, UDP, TCP | LOIC+ ≈20k–50k RPS (256 스레드) |
| **hping3** | C (CLI) | 패킷 크래프팅 | SYN/ACK/RST, raw TCP/UDP/ICMP | --flood: L3/L4 ~100k–1M pps (원리) |
| **dossal v0.5** | Python asyncio | 6 모드 엔진 | HTTP/HTTPS/WS/TCP/UDP/H2 | **측정: 52k (http), 23k (https), 13k (h2)** |

## dossal v0.5 실제 측정 (로컬)

| 모드 | 대상 | RPS | 에러 |
|---|---|---:|---:|
| http | node-victim:8080 | **51,857** | 0 |
| https | cf-sim:8443 | **22,656** | 19 (cf-sim 429 shedding) |
| h2 | cf-sim:8444 | **13,168** | 0 |
| h2 | cf-sim:8444 (50c) | **13,168** | 0 |

## 모드별 정면 비교

### HTTP L7 프러퍼 (LOIC/HOIC의 주 무대)
- **LOIC**: 단일 GUI, `HTTP GET` + `TCP` + `UDP`만. 소켓당 1 req/응답, 기본 500 소켓. 단일 호스트 L7에서 대략 **10k–30k RPS**가 실측 상한 (C 코드지만 GTK 이벤트 루프 병목).
- **HOIC**: LOIC 클론 + booster 스크립트 (GenericBoost). 스레드 256까지. 대략 **20k–50k RPS**.
- **dossal v0.5**: **51,857 RPS** (20 연결, single-loop, no-drain). 20 연결만으로 LOIC 기본 구성을 상회, HOIC와 동급. 100+ 연결 시 Python asyncio 한계까지 확장 가능.
- **판정**: LOIC 대비 **위쪽**. HOIC 대비 **동급~소폭 앞**. 단일 파일 CLI + JSON 통계 + HTTPS/H2까지 지원.

### HTTPS/TLS 프러퍼
- **LOIC**: HTTPS 지원 X (보안 컨텍스트 무시).
- **HOIC**: HTTPS 지원 X (booster로 가능하지만 제한적).
- **dossal v0.5**: **22,656 RPS** (TLS 1.3, keep-alive, single-loop). LOIC/HOIC에서 HTTPS 프러퍼는 사실상 불가능.
- **판정**: **차별화**. TLS 프러퍼 가능 = Cloudflare 엣지 직접 타격 가능.

### HTTP/2 프러퍼
- **LOIC**: X
- **HOIC**: X
- **hping3**: X (L4 이하만)
- **dossal v0.5**: **13,168 RPS** (0 에러, 50 연결, multiplexed streams). LOIC/HOIC에서 H2 프러퍼 불가.
- **판정**: **차별화**. H2 프러퍼 가능 = 현대 엣지(nghttpd, Caddy, Cloudflare) 타격 가능.

### SYN/ACK (L3/L4 프로토콜 공격)
- **hping3**: `--flood -S`로 SYN flood, `--ack`로 ACK flood, `--scan`로 포트 스캔. 원리상 **100k–1M pps** (C + raw socket).
- **LOIC/HOIC**: TCP flood (SYN)만. 대략 **10k–50k pps**.
- **dossal v0.5**: **아직 미구현** (다음 루프 목표). TCP raw flood + WebSocket flood는 지원.
- **판정**: hping3 대비 **부족** — SYN/ACK 모드가 들어오면 동급.

### raw TCP/UDP 프러퍼
- **hping3**: raw socket, 패크크래프팅. **100k+ pps**.
- **LOIC/HOIC**: TCP/UDP flood. **10k–50k pps**.
- **dossal v0.5**: TCP raw byte flood + UDP datagram flood (asyncio). 단일 호스트 **수만~수십만 pps**.
- **판정**: 동급~약소. raw socket 기반 SYN/ACK가 오면 hping3와 정면 경쟁.

### WebSocket 프러퍼
- **LOIC/HOIC/hping3**: 전부 X
- **dossal v0.5**: O (upgrade flood, masked frames)
- **판정**: **차별화** — WS 기반 백엔드(서버推送, realtime API) 타격 가능.

## 종합 판정

| 기준 | dossal v0.5 vs |
|---|---|
| **LOIC** | **위** (모드·HTTPS·H2·JSON·CLI 모두 우위, RPS도 상회) |
| **HOIC** | **동급~위** (L7 RPS 동급, 모드·HTTPS·H2 우위, GUI 없음을 제외) |
| **hping3** | **동급** (L7·HTTPS·H2·WS 우위, L3/L4 raw/SYN부족) — SYN/ACK가 오면 동급이상 |

## dossal만의 차별점
1. **6 프로토콜 모드 단일 CLI**: http/https/ws/tcp/udp/h2 — LOIC/HOIC는 2-3개, hping3는 L4 이하
2. **HTTPS + HTTP/2 프러퍼**: LOIC/HOIC 불가능
3. **JSON 통계**: RPS, bytes, errors — 자동 리포트
4. **단일 파일**: `dossal.py` 하나, 의존성 h2 하나만
5. **cf-sim 통합**: Cloudflare 유사 엣지 시뮬레이터로 로컬 검증 (429 shedding 확인)

## 한계
- Python asyncio: raw C (hping3)와 L3/L4 raw 프러퍼 pps는 차이
- SYN/ACK, gRPC, QUIC/HTTP3 미구현
- 단일 프로세스 (멀티코어 병렬还不是)
- GUI 없음 (CLI만)

## 다음 루프 목표
1. **SYN/ACK 모드** (raw socket, `--mode syn`) → hping3 L3/L4 동급
2. **victim impact score** (CPU/메모리 샘플링)
3. **멀티 모드 동시 실행** 대시보드
4. **gRPC streaming** 모드
5. **QUIC/HTTP3** 모드
