#!/usr/bin/env python3
"""Simple test: send preface + HEADERS, read all response data with longer timeout."""
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
    print("Connected")
    
    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    writer.write(conn.data_to_send())
    await writer.drain()
    print("Sent preface")
    
    # Send request immediately
    headers = [
        (':method', 'GET'),
        (':scheme', 'https'),
        (':authority', host),
        (':path', '/'),
        ('user-agent', 'test/1.0'),
    ]
    stream_id = conn.get_next_available_stream_id()
    conn.send_headers(stream_id, headers, end_stream=True)
    writer.write(conn.data_to_send())
    await writer.drain()
    print(f"Sent request on stream {stream_id}")
    
    # Read all data for 3 seconds
    total = b''
    deadline = time.time() + 3.0
    while time.time() < deadline:
        try:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=0.5)
            if not chunk:
                break
            total += chunk
            print(f"Received {len(chunk)} bytes")
            events = conn.receive_data(chunk)
            for event in events:
                if isinstance(event, ResponseReceived):
                    print(f"  Response: {dict(event.headers)}")
                elif isinstance(event, DataReceived):
                    print(f"  Data: {event.data[:50]}")
        except asyncio.TimeoutError:
            continue
    
    print(f"Total: {len(total)} bytes")
    writer.close()
    await writer.wait_closed()

asyncio.run(test())
