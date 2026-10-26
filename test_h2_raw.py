#!/usr/bin/env python3
"""Test h2 connection with raw socket to see exactly what's happening."""
import ssl, socket, time, struct

def test():
    host, port = '127.0.0.1', 8444
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(['h2'])
    
    print(f"Connecting to {host}:{port}...")
    with socket.create_connection((host, port), timeout=2) as sock:
        with ctx.wrap_socket(sock, server_hostname='localhost') as ssock:
            print(f"TLS handshake complete, ALPN: {ssock.selected_alpn_protocol()}")
            
            # Send H2 preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + empty SETTINGS
            preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
            settings_frame = b'\x00\x00\x00\x04\x00\x00\x00\x00\x00'  # Empty SETTINGS
            ssock.sendall(preface + settings_frame)
            print(f"Sent preface + SETTINGS ({len(preface + settings_frame)} bytes)")
            
            # Read server SETTINGS
            time.sleep(0.1)
            ssock.settimeout(1.0)
            data = ssock.recv(1024)
            print(f"Received {len(data)} bytes from server")
            if len(data) >= 9:
                length = struct.unpack('!I', b'\x00' + data[0:3])[0]
                frame_type = data[3]
                flags = data[4]
                stream_id = struct.unpack('!I', b'\x00' + data[5:9])[0]
                print(f"  Frame: type={frame_type}, flags={flags}, stream={stream_id}, length={length}")
            
            # Send empty SETTINGS ACK
            ack_frame = b'\x00\x00\x00\x04\x01\x00\x00\x00\x00'  # SETTINGS with ACK flag
            ssock.sendall(ack_frame)
            print(f"Sent SETTINGS ACK")
            
            # Send HEADERS frame (simplified - just the frame header for now)
            # Actually, let's send a proper HEADERS frame with HPACK
            # For simplicity, send a minimal HEADERS frame
            headers_payload = b'\x00' * 10  # Minimal/invalid HPACK for testing
            headers_frame = struct.pack('!I', len(headers_payload))[1:] + b'\x01\x05\x00\x00\x00\x01' + headers_payload
            ssock.sendall(headers_frame)
            print(f"Sent HEADERS frame ({len(headers_frame)} bytes)")
            
            # Try to read response
            time.sleep(0.2)
            try:
                data = ssock.recv(1024)
                print(f"Received {len(data)} bytes response")
                if data:
                    print(f"  Response bytes: {data[:20].hex()}")
            except socket.timeout:
                print("Timeout waiting for response")
    
    print("Done")

test()
