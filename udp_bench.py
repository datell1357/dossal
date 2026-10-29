#!/usr/bin/env python3
"""UDP PPS benchmark: pure sendto vs thread vs async"""
import socket, time, threading

PORT = 9999
HOST = '127.0.0.1'
PAYLOAD = b'B' * 1400
DURATION = 2

# 1. Pure sendto (single thread)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
count = 0
t0 = time.time()
while time.time() - t0 < DURATION:
    sock.sendto(PAYLOAD, (HOST, PORT))
    count += 1
t1 = time.time()
sock.close()
print(f"Pure sendto (1 thread): {count/(t1-t0):>10,.0f} pps")

# 2. Thread-based (4 threads)
def sender(results, idx, duration):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c = 0
    t0 = time.time()
    while time.time() - t0 < duration:
        for _ in range(1000):
            s.sendto(PAYLOAD, (HOST, PORT))
            c += 1
    results[idx] = c
    s.close()

for n_threads in [2, 4, 8]:
    results = [0] * n_threads
    threads = [threading.Thread(target=sender, args=(results, i, DURATION)) for i in range(n_threads)]
    for t in threads: t.start()
    for t in threads: t.join()
    total = sum(results)
    print(f"Thread-based ({n_threads} threads): {total/DURATION:>10,.0f} pps")
