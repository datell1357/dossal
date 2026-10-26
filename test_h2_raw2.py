#!/usr/bin/env python3
"""Test h2 with raw socket to see exact bytes."""
import ssl, socket, time, struct

def test():
    host, port = '127.0.0.1', 8444
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(['h2'])
    
    with socket.create_connection((host, port), timeout=2) as sock:
        with ctx.wrap_socket(sock, server_hostname='localhost') as ssock:
            # Send H2 preface
            ssock.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
            print("Sent preface")
            
            # Read server SETTINGS
            ssock.settimeout(1.0)
            data = ssock.recv(1024)
            print(f"Received {len(data)} bytes from server")
            
            # Parse and print all frames
            offset = 0
            while offset + 9 <= len(data):
                length = int.from_bytes(data[offset:offset+3], 'big')
                frame_type = data[offset+3]
                flags = data[offset+4]
                stream_id = int.from_bytes(data[offset+5:offset+9], 'big') & 0x7FFFFFFF
                type_name = {0:'DATA',1:'HEADERS',2:'PRIORITY',3:'RST_STREAM',4:'SETTINGS',5:'PUSH_PROMISE',6:'PING',7:'GOAWAY',8:'WINDOW_UPDATE',9:'CONTINUATION'}.get(frame_type, 'UNKNOWN')
                print(f"  Frame: {type_name}, stream={stream_id}, length={length}")
                offset += 9 + length
            
            # Send SETTINGS ACK (empty SETTINGS frame with ACK flag)
            ack = b'\x00\x00\x00\x04\x01\x00\x00\x00\x00'
            ssock.sendall(ack)
            print("Sent SETTINGS ACK")
            
            # Wait a bit
            time.sleep(0.1)
            
            # Send a minimal HEADERS frame (just the frame header + dummy HPACK)
            # For a real test, we'd need proper HPACK encoding
            # Let's send a HEADERS frame with END_STREAM and END_HEADERS flags
            # Stream ID 1, flags 0x05 (END_STREAM | END_HEADERS)
            headers_payload = b'\x00' * 5  # Minimal HPACK (invalid but for testing)
            headers_frame = struct.pack('!I', len(headers_payload))[1:] + b'\x01\x05\x00\x00\x00\x01' + headers_payload
            ssock.sendall(headers_frame)
            print(f"Sent HEADERS frame ({len(headers_frame)} bytes)")
            
            # Try to read response
            time.sleep(0.5)
            try:
                ssock.settimeout(1.0)
                data = ssock.recv(1024)
                print(f"Received {len(data)} bytes response")
                if data:
                    offset = 0
                    while offset + 9 <= len(data):
                        length = int.from_bytes(data[offset:offset+3], 'big')
                        frame_type = data[offset+3]
                        flags = data[offset+4]
                        stream_id = int.from_bytes(data[offset+5:offset+9], 'big') & 0x7FFFFFFF
                        type_name = {0:'DATA',1:'HEADERS',2:'PRIORITY',3:'RST_STREAM',4:'SETTINGS',5:'PUSH_PROMISE',6:'PING',7:'GOAWAY',8:'WINDOW_UPDATE',9:'CONTINUATION'}.get(frame_type, 'UNKNOWN')
                        print(f"  Response frame: {type_name}, stream={stream_id}, length={length}")
                        offset += 9 + length
            except socket.timeout:
                print("Timeout - no response")
    
    print("Done")

test()
