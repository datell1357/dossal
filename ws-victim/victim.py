#!/usr/bin/env python3
"""
ws-victim: WebSocket server for dossal wsm testing.
Accepts WS upgrade, reads frames, responds with pong.
"""
import asyncio
import hashlib
import base64
import struct
import json

PORT = 8090

async def handle(reader, writer):
    """WebSocket 업그레이드 + 프레임 처리."""
    # Read HTTP upgrade request
    data = await reader.readuntil(b'\r\n\r\n')
    if b'Upgrade: websocket' not in data:
        writer.close()
        return
    # Extract Sec-WebSocket-Key
    key = b''
    for line in data.split(b'\r\n'):
        if line.lower().startswith(b'sec-websocket-key:'):
            key = line.split(b':', 1)[1].strip()
    # Compute accept key
    accept = base64.b64encode(
        hashlib.sha1(key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest()
    ).decode()
    # Send 101 response
    writer.write(
        b'HTTP/1.1 101 Switching Protocols\r\n'
        b'Upgrade: websocket\r\n'
        b'Connection: Upgrade\r\n'
        b'Sec-WebSocket-Accept: ' + accept.encode() + b'\r\n\r\n'
    )
    await writer.drain()
    # Read WS frames in a loop
    try:
        while True:
            # Read frame header
            header = await reader.readexactly(2)
            b1, b2 = header[0], header[1]
            opcode = b1 & 0x0F
            masked = (b2 & 0x80) != 0
            length = b2 & 0x7F
            if length == 126:
                ext = await reader.readexactly(2)
                length = struct.unpack('!H', ext)[0]
            elif length == 127:
                ext = await reader.readexactly(8)
                length = struct.unpack('!Q', ext)[0]
            mask = b''
            if masked:
                mask = await reader.readexactly(4)
            payload = b''
            if length > 0:
                payload = await reader.readexactly(length)
            if masked:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            # Pong for ping
            if opcode == 0x9:
                resp = b'\x8A' + struct.pack('!B', 0x80 | len(payload)) + mask + payload
                writer.write(resp)
                await writer.drain()
            # Text/binary: just consume
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()

async def main():
    """WS victim 메인 (port 8090)."""
    server = await asyncio.start_server(handle, '127.0.0.1', PORT)
    print(f'ws-victim listening on {PORT}', flush=True)
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
