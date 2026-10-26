#!/usr/bin/env python3
"""Test multiple workers without any close operations."""
import asyncio, ssl, time

async def _read_http_response(reader):
    header_data = b''
    while b'\r\n\r\n' not in header_data:
        chunk = await asyncio.wait_for(reader.read(1024), timeout=1.0)
        if not chunk:
            return b''
        header_data += chunk
    header_end = header_data.find(b'\r\n\r\n')
    body_start = header_end + 4
    body = header_data[body_start:]
    for line in header_data[:header_end].decode('latin1').split('\r\n'):
        if line.lower().startswith('content-length:'):
            content_length = int(line.split(':', 1)[1].strip())
            while len(body) < content_length:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=1.0)
                if not chunk: break
                body += chunk
            body = body[:content_length]
            break
    return header_data[:body_start] + body

async def worker(name, stop):
    host, port = '127.0.0.1', 8443
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
    req = f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\nUser-Agent: test\r\n\r\n'
    count = 0
    while not stop.is_set():
        try:
            writer.write(req.encode())
            await writer.drain()
            resp = await _read_http_response(reader)
            count += 1
        except Exception:
            break
    # NO close at all - let asyncio cleanup handle it
    return count

async def main():
    stop = asyncio.Event()
    async def timed_finish():
        await asyncio.sleep(3)
        stop.set()
    
    finish_task = asyncio.create_task(timed_finish())
    workers = [asyncio.create_task(worker(i, stop)) for i in range(3)]
    
    start = time.time()
    results = await asyncio.gather(*workers, return_exceptions=True)
    elapsed = time.time() - start
    
    if not finish_task.done():
        finish_task.cancel()
    
    total = sum(r for r in results if isinstance(r, int))
    print(f'{total} requests in {elapsed:.2f}s')

asyncio.run(main())
print('DONE')
