# dossal — 종합 DoS 스트레스 테스트 엔진

## 현재 상태
- **dossal v4.3** (Python asyncio + multiprocessing) — 24개 공격 모드, 멀티모드, 자동 모드, IP 스푸핑, 프록시, CF bypass, 봇넷, GUI, 실시간 차트, HTML 리포트.
- **cf-sim v0.8** (Cloudflare 유사 엣지 시뮬레이터) — 레이트리밋, 메트릭, h1/h2.
- 로컬 대상 전용 — 실전/공개 서버 테스트 금지.

## 빠른 시작

### GUI (원클릭)
```bash
python3 dossal_gui.py
```
URL 입력 → START ATTACK 클릭. 체크박스로 스푸핑/스텔스/회복 선택.

### CLI
```bash
# 단일 모드
python3 dossal.py --mode raw --url http://target:8080 --duration 10 --threads 8

# 멀티모드 (raw + UDP + SYN 동시)
python3 dossal.py --combo web --url http://target:8080 --duration 10 --threads 16

# 자동 모드 (프로토콜 감지 + 최적 모드)
python3 dossal.py --auto --url https://target:443 --duration 30 --threads 8

# 스푸핑 + 스텔스 + 자동회복
python3 dossal.py --mode raw --url http://target:8080 --duration 30 --spoof 100 --stealth --recovery

# 시뮬레이션 (공격 없이 예측)
python3 dossal.py --dry-run --url https://target.com --threads 8
```

## 공격 모드 (24개)

| 모드 | 설명 |
|---|---|
| http | HTTP/1.1 keep-alive 요청 폭주 (asyncio) |
| https | TLS 1.3 keep-alive 요청 폭주 (asyncio) |
| httpsmp | TLS 1.3 0-RTT raw socket 폭주 (멀티프로세스) |
| raw | HTTP/1.1 raw socket 폭주 (멀티프로세스, 최고 RPS) |
| h2 | HTTP/2 멀티플렉싱 요청 폭주 (429 감지 + CF bypass) |
| h2mp | HTTP/2 멀티프로세스 (N개 연결) |
| h3mp | HTTP/3 (QUIC Initial + H3 프레임) 멀티프로세스 |
| grpc | gRPC (HTTP/2 + 프레임) 요청 폭주 |
| grpcmp | gRPC raw socket 폭주 (멀티프로세스) |
| quic | QUIC/UDP 데이터그램 폭주 (멀티프로세스) |
| udp | raw UDP 데이터그램 폭주 (멀티프로세스, IP 스푸핑) |
| tcp | raw TCP 바이트 폭주 (멀티프로세스) |
| syn | TCP SYN flood (연결만, IP_HDRINCL) |
| synack | TCP SYN-ACK flood |
| rst | TCP RST flood (SO_LINGER 중단) |
| fin | TCP FIN flood (정상 close) |
| websocket | WebSocket 업그레이드 + 프레임 폭주 |
| wsm | WebSocket 프레임 폭주 (멀티프로세스) |
| slowloris | 느린 HTTP 헤더 드립 (연결 유지) |
| dns | DNS amplification (UDP 쿼리 폭주) |
| icmp | ICMP flood (ping 폭주) |
| ssdp | SSDP/UPnP flood (IoT 타격) |
| ntp | NTP amplification (monlist 쿼리) |
| memcached | Memcached amplification (GET 쿼리) |

## combo (동시 공격)

| combo | 포함 모드 |
|---|---|
| web | raw + udp + syn |
| full | raw + udp + syn + rst |
| tls | httpsmp + h2 + udp (TLS fingerprint 랜덤화) |
| proto | grpcmp + h2 + udp |
| amplify | dns + icmp + ssdp + ntp + memcached |

## 주요 옵션

| 옵션 | 설명 |
|---|---|
| --url URL | 대상 URL (필수) |
| --duration SEC | 공격 시간 (기본 10초) |
| --threads N | 프로세스 수 (기본 8, 최대 32) |
| --mode MODE | 공격 모드 (쉼표로 다중 선택) |
| --combo NAME | combo 프리셋 (web/full/tls/proto/amplify) |
| --auto | 프로토콜 자동 감지 + 최적 모드 |
| --spoof N | 스푸핑 IP 수 (RFC 5737 TEST-NET) |
| --stealth | 스텔스 모드: 스푸핑 IP만 사용 |
| --recovery | 자동회복: 429 감지 → IP 교체 |
| --proxy URL | 프록시 (http:// 또는 socks5://) |
| --jitter MS | 요청 간 무작위 지연 (자연스러운 패턴) |
| --rotate-interval SEC | IP 순환 간격 (기본 5초) |
| --targets URL1,URL2 | 멀티 타겟 동시 공격 |
| --dry-run | 시뮬레이션 (공격 없이 예측) |
| --live | 실시간 스탯 출력 |
| --report FILE | HTML 리포트 생성 |
| --impact | 피해 임팩트 점수 |
| --pool FILE | 스푸핑 IP 풀 파일 |

## IP 스푸핑 & 스텔스 모드

### 원리
- **스푸핑 IP**: RFC 5737 TEST-NET-3 (203.0.113.0/24)나 랜덤 /24에서 IP 생성
- **Windows**: 관리자 권한 + raw socket + IP_HDRINCL → 진짜 소스 IP 스푸핑 (100만 IP)
- **macOS/Linux**: SOCK_DGRAM + bind() → 로컬 IP 바인딩

### 사용법
```bash
# 100개 스푸핑 IP + 스텔스 + 자동회복
python3 dossal.py --mode raw --url http://target:8080 --duration 60 --spoof 100 --stealth --recovery --threads 16
```

### 429 자동회복
- Cloudflare가 per-IP 1000 RPS 제한 → 429 수신
- dossal이 429 감지 → 해당 IP를 차단 목록에 추가
- 다음 요청은 다음 스푸핑 IP로 전송
- 전체 IP 풀이 차단되면 종료

## 프록시 지원
```bash
# HTTP 프록시
python3 dossal.py --mode raw --url http://target:8080 --proxy http://user:pass@proxy:8080 --duration 30

# SOCKS5 프록시
python3 dossal.py --mode raw --url http://target:8080 --proxy socks5://proxy:1080 --duration 30
```

## Cloudflare bypass
- **TLS fingerprint 랜덤화**: per-process cipher/ALPN/SNI 변동 (JA3 우회)
- **CF 헤더**: sec-fetch-*, sec-ch-ua, If-Modified-Since (봇 감지 우회)
- **페이로드 랜덤화**: path/UA/headers 랜덤 (시그니처 DDoS 방어 우회)
- **429 감지 + IP 교체**: per-IP 레이트리밋 우회

## 멀티 노드 봇넷
```bash
# 컨트롤러 (GUI)
python3 dossal_net.py --controller --gui --port 9999

# 워커 (멀티 머신)
python3 dossal_net.py --worker --controller-addr 10.0.0.1:9999 --id node1 --listen-port 9998
```

## Windows 가이드
1. **Python 3.10+** 설치 (python.org)
2. **의존성 설치**: `pip install h2 hpack websockets grpcio pyinstaller`
3. **관리자 권한으로 실행** (raw socket 스푸핑 필요):
   ```
   # GUI (원클릭)
   python dossal_gui.py
   
   # CLI (최대 전력)
   python dossal.py --mode raw --url http://target.com --duration 60 --threads 16 --spoof 100 --stealth --recovery
   
   # combo (TLS + UDP + SYN 동시)
   python dossal.py --combo tls --url https://target.com --duration 60 --threads 16
   ```
4. **EXE 빌드**: `pyinstaller --onefile --windowed --name dossal dossal_gui.py`

## 성능 (30코어 M2 Max)

| 모드 | 성능 |
|---|---|
| raw 24p | 143k RPS |
| httpsmp 24p | 103k RPS (0-RTT 13.6k) |
| h2 600c | 40k RPS |
| h2mp 16p | 17.6k RPS (0 err) |
| h3mp 16p | 949k pkts (317k PPS) |
| wsm 4p | 591k msg/s |
| udp 8p | 339k PPS (스푸핑) |
| dns 8p | 675k pkts |
| icmp 8p | 560k pkts |
| ssdp 8p | 680k pkts |
| ntp 8p | 720k pkts |
| memcached 8p | 720k pkts |
| syn 8p | 16k conns |
| fin 8p | 61k conns (0% err) |
| combo tls | 34.2k RPS + 204k PPS |

## 파일 구조
```
dossal.py        # 메인 엔진 (2818 LOC, 24모드, 74개 함수 한글 docstring)
dossal_gui.py    # tkinter GUI (510 LOC, 원클릭, 차트, 프로파일)
dossal_net.py    # 멀티 노드 봇넷 (304 LOC, GUI + CLI 컨트롤러)
build.sh         # PyInstaller EXE 빌드
bench.py         # 벤치마크 (24모드, --core 옵션)
cf-sim/          # Cloudflare 유사 엣지 시뮬레이터
node-victim/     # HTTP victim (port 8080)
grpc-victim/     # gRPC victim (port 50051)
quic-victim/     # QUIC/UDP victim (port 4443)
py-victim/       # UDP receiver (port 9999)
ws-victim/       # WebSocket victim (port 8090)
heavy-victim/     # CPU-heavy victim (port 8082)
```

## 버전 이력
- **v4.3**: jitter 4곳 적용 (raw/httpsmp/h2/http/https), 74개 함수 한글 docstring
- **v4.2**: TLS 1.3 0-RTT, h3mp, GUI combo, dossal_net GUI, --rotate-interval, impact score
- **v4.1**: h2mp, L4 amplification (dns/icmp/ssdp/ntp/memcached), TLS fingerprint, CF bypass, 페이로드 랜덤화, 멀티 타겟, 프록시, SYN 스푸핑, GUI 차트, 프로파일
- **v3.16**: 17모드, 멀티모드, 자동 모드, 벤치 638.9 PEAK
