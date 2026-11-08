#!/usr/bin/env python3
"""
grpc-victim: HTTP/2 gRPC-compatible server for dossal testing.
v3: multiprocessing (N workers) for parallel h2 handling.
"""
import asyncio
import ssl
import time
import os
import multiprocessing as mp
from pathlib import Path

PORT = 50051
N_WORKERS = int(os.environ.get('GRPC_VICTIM_WORKERS', 4))
HERE = Path(__file__).parent
CERT = HERE / 'cert.pem'
KEY = HERE / 'key.pem'

def ensure_cert():
    """TLS 인증서/키 생성."""
    if CERT.exists() and KEY.exists():
        return
    import subprocess
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                    '-keyout', str(KEY), '-out', str(CERT),
                    '-days', '365', '-nodes', '-subj', '/CN=localhost'],
                   check=True, capture_output=True)

ensure_cert()

def cpu_work():
    """CPU 부하 생성 (gRPC 요청 처리 시)."""
    x = 0
    for i in range(1000):
        x += i * i
    return x

async def handle_h2(reader, writer):
    """HTTP/2 gRPC 요청 처리 (최소 구현)."""
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import RequestReceived

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

def worker(port):
    """워커 프로세스에서 asyncio 이벤트 루프 실행."""
    async def _main():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(CERT), str(KEY))
        ctx.set_alpn_protocols(['h2'])
        server = await asyncio.start_server(handle_h2, '127.0.0.1', port, ssl=ctx)
        async with server:
            await server.serve_forever()
    asyncio.run(_main())

if __name__ == '__main__':
    if N_WORKERS <= 1:
        async def _single():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(CERT), str(KEY))
            ctx.set_alpn_protocols(['h2'])
            server = await asyncio.start_server(handle_h2, '127.0.0.1', PORT, ssl=ctx)
            print(f'grpc-victim listening on {PORT} (1 worker)', flush=True)
            async with server:
                await server.serve_forever()
        asyncio.run(_single())
    else:
        # Multiprocessing: each worker gets a different port
        # Main port: PORT. Workers: PORT+1, PORT+2, ...
        # For simplicity, we use a single port with SO_REUSEPORT.
        import socket
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(CERT), str(KEY))
        ctx.set_alpn_protocols(['h2'])
        
        # Use SO_REUSEPORT to allow multiple processes on the same port
        processes = []
        for i in range(N_WORKERS):
            p = mp.Process(target=worker, args=(PORT,), daemon=True)
            p.start()
            processes.append(p)
        print(f'grpc-victim listening on {PORT} ({N_WORKERS} workers)', flush=True)
        try:
            for p in processes:
                p.join()
        except KeyboardInterrupt:
            for p in processes:
                p.terminate()
            for p in processes:
                p.join()
