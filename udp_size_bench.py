#!/usr/bin/env python3
"""UDP PPS test: small vs large payloads"""
import socket, time

HOST, PORT = '127.0.0.1', 9999
DURATION = 2

for size in [64, 256, 512, 1400, 4096]:
    payload = b'B' * size
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    count = 0
    t0 = time.time()
    while time.time() - t0 < DURATION:
        sock.sendto(payload, (HOST, PORT))
        count += 1
    t1 = time.time()
    sock.close()
    pps = count / (t1 - t0)
    mbps = pps * size * 8 / 1e6
    print(f"  {size:>5d} bytes: {pps:>10,.0f} pps  ({mbps:.0f} Mbps)")
