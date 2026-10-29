#!/usr/bin/env python3
"""
dossal bench — 측정 계약 (evaluation contract)
command:    python3 bench.py
metric:     total score = sum of (rps/1000) per mode + impact_score (higher_is_better)
direction:  higher_is_better
harness_mutable: false
baseline:   (measured below, first run)

Run each mode against local victims, aggregate into one score.
"""
import json, subprocess, sys, time, os, signal

PY = sys.executable
LAB = os.path.dirname(os.path.abspath(__file__))
DOSSAL = os.path.join(LAB, 'dossal.py')

# Mode configs: (mode, url, connections, duration)
TESTS = [
    # mode, url, connections, duration — tuned to measured optima
    ('http',      'http://127.0.0.1:8080',     400, 2),   # 60k RPS at 400c
    ('https',     'https://127.0.0.1:8443',    50, 2),    # 20k RPS
    ('h2',        'https://127.0.0.1:8444',    50, 2),    # 13k RPS at 50c
    ('grpc',      'https://127.0.0.1:50051/',  20, 2),    # 420 RPS at 20c
    ('quic',      'udp://127.0.0.1:4443',      1, 2),     # 106k pps at 1c
    ('udp',       'udp://127.0.0.1:9999',      1, 2),     # 106k pps at 1c
    ('syn',       'tcp://127.0.0.1:8080',      10, 2),    # 13k conns
    ('rst',       'tcp://127.0.0.1:8080',      10, 2),    # 14k conns
    ('slowloris', 'http://127.0.0.1:8080',     10, 2),
]

def run_mode(mode, url, conns, dur):
    """Run one mode, return parsed stats."""
    cmd = [PY, DOSSAL, '--mode', mode, '--url', url,
           '--connections', str(conns), '--duration', str(dur)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=dur + 15)
        out = r.stdout.strip()
        js = out[out.find('{'):]
        return json.loads(js)
    except Exception as e:
        return {'mode': mode, 'rps': 0, 'packets': 0, 'connections_made': 0,
                'errors': 1, '_err': str(e)}

def main():
    t0 = time.time()
    results = []
    for mode, url, conns, dur in TESTS:
        stats = run_mode(mode, url, conns, dur)
        stats['_mode'] = mode
        results.append(stats)
        print(f"  {mode:12s} rps={stats.get('rps',0):>10,.0f}  "
              f"pkts={stats.get('packets',0):>8}  "
              f"conns={stats.get('connections_made',0):>6}  "
              f"err={stats.get('errors',0)}", flush=True)

    # Impact score: attack heavy-victim with http, measure
    impact_cmd = [PY, DOSSAL, '--mode', 'http', '--url', 'http://127.0.0.1:8082',
                  '--connections', '20', '--duration', '3', '--impact']
    try:
        r = subprocess.run(impact_cmd, capture_output=True, text=True, timeout=30)
        out = r.stdout.strip()
        js = out[out.find('{'):]
        impact_data = json.loads(js)
        impact = impact_data.get('impact', {})
        impact_score = impact.get('impact_score', 0)
        victim_cpu = impact.get('victim_cpu_pct', 0)
        print(f"  {'impact':12s} score={impact_score:>6.1f}  "
              f"victim_cpu={victim_cpu}%  "
              f"rps={impact_data.get('rps',0):,.0f}", flush=True)
    except Exception as e:
        impact_score = 0
        print(f"  {'impact':12s} ERROR: {e}", flush=True)

    # Total score
    total = 0
    for s in results:
        total += s.get('rps', 0) / 1000  # RPS contribution
        total += s.get('packets', 0) / 100000  # pps contribution
        total += s.get('connections_made', 0) / 1000  # conn contribution
    total += impact_score  # impact contribution
    total = round(total, 1)

    wall = time.time() - t0
    print(f"\n{'='*50}")
    print(f"TOTAL SCORE: {total}")
    print(f"Wall time: {wall:.1f}s")
    print(f"{'='*50}")

    # Save result
    out_path = os.path.join(LAB, 'logs', 'bench-result.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump({'total_score': total, 'impact_score': impact_score,
                   'wall_time': wall, 'results': results}, f, indent=2)
    print(f"Saved to {out_path}")

if __name__ == '__main__':
    main()
