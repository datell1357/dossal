"""UDP 패킷 수신 victim (port 9999). dossal udp/dns/icmp/ssdp/ntp/memcached 모드 테스트용."""
#!/usr/bin/env python3
"""UDP receiver for local DoS lab."""
import socket, os, json, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', int(os.environ.get('UDP_PORT', '9999'))))
count = 0
bytes_total = 0
while True:
    data, addr = sock.recvfrom(65535)
    count += 1
    bytes_total += len(data)
    if count % 1000 == 0:
        print(json.dumps({"packets": count, "bytes": bytes_total}), flush=True)
