#!/usr/bin/env python3
"""HTTP RPS ceiling test: where does it stop scaling?"""
import asyncio, ssl, time, json, sys

DOSSAL_PY = '/Users/yeoreum/.hermes/profiles/uac1c-ubc1c-uc790/cache/scratch/dos-lab/dossal.py'
PY = sys.executable

async def http_flood(host, port, n_conns, duration):
    """Minimal HTTP/1.1 flood: open n connections, send GET in a loop."""
    stop = asyncio.Event()
    async def timer():
        await asyncio.sleep(duration)
        stop.set()
    t = asyncio.create_task(timer())
    
    requests_count = 0
    errors = 0
    
    async def worker():
        nonlocal requests_count, errors
        try:
            reader, writer = await asyncio.open_connection(host, port)
            req = b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: keep-alive\r\n\r\n"
            while not stop.is_set():
                try:
                    writer.write(req)
                    await asyncio.wait_for(reader.read(4096), timeout=5.0)
                    requests_count += 1
                except Exception:
                    errors += 1
                    break
            writer.transport.abort()
        except Exception:
            errors += 1
    
    t0 = time.time()
    await asyncio.gather(*[worker() for _ in range(n_conns)])
    t1 = time.time()
    t.cancel()
    rps = requests_count / (t1 - t0)
    return rps, requests_count, errors

async def main():
    print("=== HTTP RPS ceiling (node-victim:8080) ===")
    for conns in [200, 400, 600, 800, 1000]:
        rps, req, err = await http_flood('127.0.0.1', 8080, conns, 2)
        print(f"  {conns:>5d} conns: {rps:>10,.0f} RPS  ({req:>8d} req, {err} err)")

asyncio.run(main())
