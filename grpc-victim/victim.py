#!/usr/bin/env python3
"""
grpc-victim: HTTP/2 gRPC-compatible server for dossal testing.
v2: lighter CPU work (10k loop), batched frame writes.
"""
import asyncio
import ssl
import time
from pathlib import Path

PORT = 50051
HERE = Path(__file__).parent
CERT = HERE / 'cert.pem'
KEY = HERE / 'key.pem'

def ensure_cert():
    if CERT.exists() and KEY.exists():
        return
    import subprocess
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                    '-keyout', str(KEY), '-out', str(CERT),
                    '-days', '365', '-nodes', '-subj', '/CN=localhost'],
                   check=True, capture_output=True)

ensure_cert()

def cpu_work():
    x = 0
    for i in range(1000):
        x += i * i
    return x

async def handle_h2(reader, writer):
    """Minimal HTTP/2 handler for gRPC testing. Batched, low-latency."""
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import RequestReceived, DataReceived, StreamEnded

    config = H2Configuration(client_side=False)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    writer.write(conn.data_to_send())
    await writer.drain()

    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
        conn.receive_data(data)
        if conn.data_to_send():
            writer.write(conn.data_to_send())
            await writer.drain()
    except asyncio.TimeoutError:
        pass

    try:
        while True:
            data = await asyncio.wait_for(reader.read(65535), timeout=5.0)
            if not data:
                break
            events = conn.receive_data(data)
            for event in events:
                if isinstance(event, RequestReceived):
                    stream_id = event.stream_id
                    x = cpu_work()
                    body = str(x).encode()
                    grpc_frame = b'\x00' + len(body).to_bytes(4, 'big') + body
                    conn.send_headers(stream_id, [
                        (b':status', b'200'),
                        (b'content-type', b'application/grpc'),
                        (b'grpc-status', b'0'),
                    ], end_stream=False)
                    conn.send_data(stream_id, grpc_frame, end_stream=True)
            out = conn.data_to_send()
            if out:
                writer.write(out)
                await writer.drain()
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERT), str(KEY))
    ctx.set_alpn_protocols(['h2'])
    server = await asyncio.start_server(handle_h2, '127.0.0.1', PORT, ssl=ctx)
    print(f'grpc-victim listening on {PORT}', flush=True)
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
