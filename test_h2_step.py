#!/usr/bin/env python3
"""Test h2 with explicit flush and separate reads."""
import asyncio, ssl, time, os
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
    
    # Send preface
    writer.write(conn.data_to_send())
    await writer.drain()
    print("Sent preface, drained")
    
    # Wait for server SETTINGS
    data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
    print(f"Received {len(data)} bytes (server SETTINGS)")
    conn.receive_data(data)
    
    # Send request
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
    print(f"Sent request on stream {stream_id}, drained")
    
    # Wait and read
    await asyncio.sleep(0.5)
    print("Reading response...")
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
        print(f"Received {len(data)} bytes response")
        events = conn.receive_data(data)
        for event in events:
            print(f"  Event: {type(event).__name__}")
            if isinstance(event, ResponseReceived):
                print(f"    Headers: {dict(event.headers)}")
            elif isinstance(event, DataReceived):
                print(f"    Data: {event.data[:50]}")
    except asyncio.TimeoutError:
        print("Timeout - no response received")
    
    writer.close()
    await writer.wait_closed()

asyncio.run(test())
