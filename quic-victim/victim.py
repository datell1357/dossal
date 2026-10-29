#!/usr/bin/env python3
"""
quic-victim: minimal QUIC/HTTP3 server for dossal testing.
Accepts raw UDP packets on port 4443.
"""
import asyncio
import socket
import time

PORT = 4443

async def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', PORT))
    sock.setblocking(False)
    
    print(f'quic-victim listening on {PORT}', flush=True)
    
    loop = asyncio.get_event_loop()
    packets = 0
    
    while True:
        try:
            data, addr = await loop.sock_recv(sock, 65535)
            packets += 1
            # Process the packet (CPU work to simulate QUIC handshake)
            if packets % 1000 == 0:
                print(f'  processed {packets} packets', flush=True)
        except (OSError, asyncio.TimeoutError):
            continue

if __name__ == '__main__':
    asyncio.run(main())
