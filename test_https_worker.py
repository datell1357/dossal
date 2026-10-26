#!/usr/bin/env python3
"""Test https_worker logic directly."""
import asyncio, ssl, time
from urllib.parse import urlparse

async def _read_http_response(reader):
    header_data = b''
    while b'\r\n\r\n' not in header_data:
        chunk = await asyncio.wait_for(reader.read(1024), timeout=1.0)
        if not chunk:
            return b''
        header_data += chunk
    
    header_end = header_data.find(b'\r\n\r\n')
    headers_part = header_data[:header_end].decode('latin1')
    body_start = header_end + 4
    body = header_data[body_start:]
    
    for line in headers_part.split('\r\n'):
        if line.lower().startswith('content-length:'):
            content_length = int(line.split(':', 1)[1].strip())
            while len(body) < content_length:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=1.0)
                if not chunk:
                    break
                body += chunk
            body = body[:content_length]
            break
    
    return header_data[:body_start] + body

async def test():
    host, port = '127.0.0.1', 8443
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    print(f"Connecting to {host}:{port}...")
    reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
    print("Connected")
    
    req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\nUser-Agent: test\r\n\r\n"
    
    for i in range(3):
        writer.write(req.encode())
        await writer.drain()
        resp = await _read_http_response(reader)
        print(f"Request {i+1}: got {len(resp)} bytes: {resp[:50]}")
    
    writer.close()
    await writer.wait_closed()
    print("Done")

asyncio.run(test())
