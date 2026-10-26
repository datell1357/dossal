#!/usr/bin/env python3
"""Test h2 connection with detailed debug output."""
import asyncio, ssl, time
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived, RequestReceived

async def test():
    host, port = '127.0.0.1', 8444
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(['h2'])
    
    print(f"Connecting to {host}:{port}...")
    reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
    print(f"Connection established")
    
    # Check ALPN
    transport = writer.transport
    if hasattr(transport, 'get_extra_info'):
        alpn = transport.get_extra_info('selected_alpn_protocol')
        print(f"ALPN: {alpn}")
    
    config = H2Configuration(client_side=True)
    conn = H2Connection(config=config)
    conn.initiate_connection()
    
    preface = conn.data_to_send()
    print(f"Sending preface ({len(preface)} bytes): {preface[:24]}...")
    writer.write(preface)
    await writer.drain()
    
    # Wait a bit for server SETTINGS
    await asyncio.sleep(0.1)
    data = await asyncio.wait_for(reader.read(8192), timeout=1.0)
    print(f"Received from server ({len(data)} bytes): {data[:24]}...")
    
    events = conn.receive_data(data)
    print(f"Events: {events}")
    
    # Send a request
    headers = [
        (':method', 'GET'),
        (':scheme', 'https'),
        (':authority', host),
        (':path', '/'),
        ('user-agent', 'test/1.0'),
    ]
    stream_id = conn.get_next_available_stream_id()
    print(f"Sending request on stream {stream_id}")
    conn.send_headers(stream_id, headers, end_stream=True)
    data = conn.data_to_send()
    print(f"Sending request data ({len(data)} bytes)")
    writer.write(data)
    await writer.drain()
    
    # Wait for response
    await asyncio.sleep(0.1)
    data = await asyncio.wait_for(reader.read(8192), timeout=1.0)
    print(f"Received response data ({len(data)} bytes): {data[:24]}...")
    
    events = conn.receive_data(data)
    print(f"Response events: {events}")
    for event in events:
        if isinstance(event, ResponseReceived):
            print(f"  Response received: {event.headers}")
        elif isinstance(event, DataReceived):
            print(f"  Data received: {event.data[:50]}")
    
    writer.close()
    await writer.wait_closed()
    print("Done")

asyncio.run(test())
