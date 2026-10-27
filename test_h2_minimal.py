#!/usr/bin/env python3
"""Minimal h2 test: preface, wait for server SETTINGS, then request, then read."""
import asyncio, ssl, time
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived

async def test():
    host, port = '127.0.0.1', 8444
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(['h2'])

    reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
    print("Connected", flush=True)

    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    writer.write(conn.data_to_send())
    await writer.drain()
    print(f"Sent preface + SETTINGS ({len(conn.data_to_send())} bytes pending after)", flush=True)

    # Wait for server SETTINGS
    try:
        data = await asyncio.wait_for(reader.read(8192), timeout=3.0)
        print(f"Received {len(data)} bytes from server", flush=True)
        events = conn.receive_data(data)
        for e in events:
            print(f"  Event: {type(e).__name__}", flush=True)
    except asyncio.TimeoutError:
        print("Timeout waiting for server SETTINGS", flush=True)

    # Now send request
    headers = [
        (':method', 'GET'),
        (':scheme', 'https'),
        (':authority', host),
        (':path', '/'),
        ('user-agent', 'test/1.0'),
    ]
    stream_id = conn.get_next_available_stream_id()
    conn.send_headers(stream_id, headers, end_stream=True)
    out = conn.data_to_send()
    writer.write(out)
    await writer.drain()
    print(f"Sent request on stream {stream_id} ({len(out)} bytes)", flush=True)

    # Read response for 3 seconds
    total = b''
    deadline = time.time() + 3.0
    while time.time() < deadline:
        try:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=0.5)
            if not chunk:
                break
            total += chunk
            print(f"Received {len(chunk)} bytes", flush=True)
            events = conn.receive_data(chunk)
            for event in events:
                if isinstance(event, ResponseReceived):
                    print(f"  Response: {dict(event.headers)}", flush=True)
                elif isinstance(event, DataReceived):
                    print(f"  Data: {event.data[:50]}", flush=True)
        except asyncio.TimeoutError:
            continue

    print(f"Total: {len(total)} bytes", flush=True)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass

asyncio.run(test())
