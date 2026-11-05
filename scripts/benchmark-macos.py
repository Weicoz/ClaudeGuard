#!/usr/bin/env python3
"""Measure an isolated native guard. Never applies hosts/pf rules or kills apps."""
import argparse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time

import psutil


HARNESS = r'''
class BenchmarkGuard: AppDelegate {
    var policyProcesses = 0
    var helperRequests = 0
    var verifiedProbes = 0
    var failedProbes = 0
    override func detectExits(mode: String) -> [String: String] {
        let exits = super.detectExits(mode: mode)
        if exits.isEmpty { failedProbes += 1 } else { verifiedProbes += 1 }
        return exits
    }
    override func apply(from previous: GuardState, to new: GuardState) { enforcementConfirmed = true }
    override func setupAppLaunchInterceptor() {}
    override func runHelper(_ cmd: String, _ a1: String, _ a2: String) -> Process? {
        helperRequests += 1
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try! task.run()
        return task
    }
    override func runPolicy(action: String, request: [String: Any]) -> [String: Any] {
        policyProcesses += 1
        return super.runPolicy(action: action, request: request)
    }
}
let delegate = BenchmarkGuard()
delegate.headless = true
delegate.configPath = CommandLine.arguments[1]
delegate.eventLogPath = delegate.configPath + ".events"
delegate.policyScriptPath = CommandLine.arguments[3]
if CommandLine.arguments[2] != "live" {
    delegate.httpServices = (0..<5).map { CommandLine.arguments[2] + "/" + String($0) }
}
precondition(delegate.acquireDaemonLock())
delegate.startGuard()
var warmPolicies = 0
var warmHelpers = 0
func childrenCPU() -> Double {
    var usage = rusage()
    getrusage(RUSAGE_CHILDREN, &usage)
    return Double(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) + Double(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1000000
}
var warmChildCPU = 0.0
Timer.scheduledTimer(withTimeInterval: 10, repeats: false) { _ in
    delegate.workQueue.sync {
        warmPolicies = delegate.policyProcesses
        warmHelpers = delegate.helperRequests
    }
    warmChildCPU = childrenCPU()
}
signal(SIGTERM, SIG_IGN)
let stop = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
stop.setEventHandler {
    delegate.workQueue.sync {
    let counts: [String: Any] = ["policy_processes": delegate.policyProcesses, "helper_requests": delegate.helperRequests,
                  "child_cpu_seconds_after_warmup": childrenCPU() - warmChildCPU,
                  "verified_probes": delegate.verifiedProbes, "failed_probes": delegate.failedProbes,
                  "policy_processes_after_warmup": delegate.policyProcesses - warmPolicies,
                  "helper_requests_after_warmup": delegate.helperRequests - warmHelpers]
    print(String(data: try! JSONSerialization.data(withJSONObject: counts), encoding: .utf8)!)
    exit(0)
    }
}
stop.resume()
Timer.scheduledTimer(withTimeInterval: Double(CommandLine.arguments[4])!, repeats: false) { _ in exit(2) }
RunLoop.main.run()
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=60, help='steady-state sample window, at least 15 seconds')
    parser.add_argument('--live-http', action='store_true', help='use project HTTPS providers and the existing HTTP proxy; otherwise loopback only')
    args = parser.parse_args()
    if sys.platform != 'darwin' or args.seconds < 15:
        parser.error('requires macOS and --seconds >= 15')
    repo = Path(__file__).resolve().parents[1]
    counts = Counter()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            counts[self.path] += 1
            body = b'203.0.113.10'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    with tempfile.TemporaryDirectory(prefix='claudeguard-benchmark-') as directory, ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
        root = Path(directory)
        source = (repo / 'src/main.swift').read_text().split('\n// MARK: - Entry point')[0]
        (root / 'main.swift').write_text(source + HARNESS)
        subprocess.run(['swiftc', '-O', str(root / 'main.swift'), '-o', str(root / 'guard')], check=True, capture_output=True, timeout=60)
        data = {'ip_check_mode': 'http', 'allowed_ips': ['0.0.0.0/0', '::/0'], 'check_interval': 3,
                'protection_enabled': True, 'detect_ip_change': True, 'allow_unknown_ip': True,
                'block_auto_updates': False}
        if args.live_http:
            actual = json.loads((Path.home() / '.config/claudeguard/config.json').read_text())
            data['http_proxy'] = actual.get('http_proxy', '')
        config = root / 'config.json'
        config.write_text(json.dumps(data))
        config.chmod(0o600)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        endpoint = 'live' if args.live_http else f'http://127.0.0.1:{server.server_port}'
        child = subprocess.Popen([str(root / 'guard'), str(config), endpoint, str(repo / 'src/policy_cli.py'), str(args.seconds * 3 + 60)], stdout=subprocess.PIPE, text=True)
        try:
            process = psutil.Process(child.pid)
            time.sleep(10)
            before = sum(process.cpu_times()[:2])
            started = time.monotonic()
            rss, children = [], []
            for _ in range(args.seconds):
                rss.append(process.memory_info().rss)
                children.append(len(process.children(recursive=True)))
                time.sleep(1)
            elapsed = time.monotonic() - started
            cpu = (sum(process.cpu_times()[:2]) - before) / elapsed * 100
            sample = root / 'sample.txt'
            subprocess.run(['sample', str(child.pid), '1', '-file', str(sample)], check=True, capture_output=True, timeout=20)
            match = re.search(r'Physical footprint:\s+([\d.]+)([KMGT]?)', sample.read_text())
            if not match:
                raise RuntimeError('sample did not report physical footprint')
            footprint = float(match[1]) * 1024 ** (' KMGT'.index(match[2]) if match[2] else 0)
            peak = re.search(r'Physical footprint \(peak\):\s+([\d.]+)([KMGT]?)', sample.read_text())
            if not peak:
                raise RuntimeError('sample did not report peak physical footprint')
            peak_bytes = float(peak[1]) * 1024 ** (' KMGT'.index(peak[2]) if peak[2] else 0)
            child.terminate()
            output = json.loads(child.communicate(timeout=15)[0])
            total_cpu = cpu + output['child_cpu_seconds_after_warmup'] / elapsed * 100
            print(json.dumps({'scope': 'isolated HTTP guard; enforcement and repair side effects replaced',
                              'transport': 'live HTTPS' if args.live_http else 'loopback HTTP',
                              'sample_seconds': args.seconds, 'actual_elapsed_seconds': round(elapsed, 3),
                              'cpu_percent': round(total_cpu, 4), 'cpu_main_percent': round(cpu, 4),
                              'physical_footprint_mb': round(footprint / 1000000, 3),
                              'physical_footprint_peak_mb': round(peak_bytes / 1000000, 3),
                              'rss_mb_min': round(min(rss) / 1000000, 3), 'rss_mb_max': round(max(rss) / 1000000, 3),
                              'max_children_after_warmup': max(children), 'process_counts': output,
                              'loopback_requests': sum(counts.values()) if not args.live_http else None,
                              'meets_idle_targets': total_cpu < 1 and footprint < 10000000 and peak_bytes < 10000000 and max(children) == 0
                              and output['verified_probes'] > 0
                              and output['policy_processes_after_warmup'] == 0 and output['helper_requests_after_warmup'] == 0}, ensure_ascii=False, indent=2))
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)
            server.shutdown()
            thread.join(timeout=3)


if __name__ == '__main__':
    main()
