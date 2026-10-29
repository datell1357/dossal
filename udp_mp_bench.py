#!/usr/bin/env python3
"""UDP PPS: multiprocessing test"""
import socket, time, os, multiprocessing as mp

HOST, PORT = '127.0.0.1', 9999
DURATION = 2

def udp_sender(payload, stop_event, result_queue):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    count = 0
    t0 = time.time()
    while not stop_event.is_set() and time.time() - t0 < DURATION:
        for _ in range(1000):
            sock.sendto(payload, (HOST, PORT))
            count += 1
    result_queue.put(count)
    sock.close()

def test_mp(n_procs, size=1400):
    payload = b'B' * size
    stop = mp.Event()
    q = mp.Queue()
    procs = [mp.Process(target=udp_sender, args=(payload, stop, q)) for _ in range(n_procs)]
    for p in procs: p.start()
    for p in procs: p.join()
    total = 0
    while not q.empty():
        total += q.get()
    pps = total / DURATION
    print(f"  MP {n_procs:>2d} procs, {size}B: {pps:>10,.0f} pps")
    return pps

print("=== Multiprocessing UDP test ===")
test_mp(1, 64)
test_mp(2, 64)
test_mp(4, 64)
test_mp(2, 1400)
test_mp(4, 1400)
