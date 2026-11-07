import socket, threading

def handle(conn, addr):
    try:
        data = conn.recv(4096).decode()
        if 'CONNECT' in data:
            target = data.split()[1]
            host, port = target.split(':')
            upstream = socket.create_connection((host, int(port)))
            conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            def f1():
                while True:
                    d = conn.recv(65535)
                    if not d: break
                    upstream.sendall(d)
            def f2():
                while True:
                    d = upstream.recv(65535)
                    if not d: break
                    conn.sendall(d)
            t1 = threading.Thread(target=f1, daemon=True)
            t2 = threading.Thread(target=f2, daemon=True)
            t1.start(); t2.start()
        conn.close()
    except: pass

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 18888))
s.listen(50)
print('proxy on 18888', flush=True)
while True:
    c, a = s.accept()
    threading.Thread(target=handle, args=(c, a), daemon=True).start()
