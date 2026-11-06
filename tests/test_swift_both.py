"""Exercise the actual Swift decision functions without starting the daemon."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift compiler required')
class SwiftBothTests(unittest.TestCase):
    def test_both_verdict_matrix(self):
        source = (Path(__file__).resolve().parents[1] / 'src/main.swift').read_text()
        source = source.split('\n// MARK: - Entry point')[0]
        harness = r'''
let good = "203.0.113.10"
precondition(AppDelegate.isClaudeCLIPath("/opt/bin/claude"))
precondition(!AppDelegate.isClaudeCLIPath("/opt/bin/ClaudeGuardMenuBar"))
precondition(!AppDelegate.isClaudeCLIPath("/usr/bin/python3", command: "python3 /app/claude-w kill"))
precondition(AppDelegate.isClaudeCLIPath("/opt/bin/node", command: "node /npm/@anthropic-ai/claude-code/cli.js"))
precondition(!AppDelegate.isClaudeCLIPath("/opt/bin/node", command: "node unrelated.js @anthropic-ai/claude-code/cli.js"))
let bad = "203.0.113.20"
let cases: [([String: String], String)] = [
    (["http": good, "stun": good], "allowed"),
    (["http": good, "stun": bad], "blocked"),
    (["stun": bad, "http": good], "blocked"),
    (["http": bad, "stun": good], "blocked"),
    (["http": bad, "stun": bad], "blocked"),
    (["http": good], "offline"),
    (["stun": good], "offline"),
    ([:], "offline"),
    (["stun": bad], "blocked"),
    (["http": bad], "blocked")
]
for (ips, expected) in cases {
    let state = AppDelegate.bothState(ips, allowedList: [good])
    let result: String
    switch state {
    case .allowed: result = "allowed"
    case .blocked: result = "blocked"
    case .offline: result = "offline"
    case .disabled: result = "disabled"
    }
    precondition(result == expected, "\(ips): got \(result), expected \(expected)")
}
if case .allowed = AppDelegate.bothState(["http": good, "stun": bad], allowedList: ["203.0.113.0/24"]) {} else {
    fatalError("Both distinct whitelisted IPs must pass")
}
precondition(AppDelegate.parseHTTPIP(Data("Too many requests".utf8)) == nil)
precondition(AppDelegate.parseHTTPIP(Data("203.0.113.10".utf8)) == good)
precondition(AppDelegate.parseHTTPIP(Data("2001:db8::1".utf8)) == "2001:db8::1")
let native = AppDelegate()
native.menu = NSMenu()
native.rebuildMenu()
let settingsMenu = native.menu.items.first { $0.title == "设置" }!.submenu!
let firewallMenu = settingsMenu.items.first { $0.title == "Claude 直连防火墙" }!.submenu!
precondition(firewallMenu.items.compactMap { $0.representedObject as? String } == ["status", "preview", "install", "uninstall", "verify"], "Firewall menu actions are missing or misrouted")
native.eventLogPath = URL(fileURLWithPath: CommandLine.arguments[2]).deletingLastPathComponent().appendingPathComponent("events.jsonl").path
native.logEvent("test_event", fields: ["reason": "测试"])
let log = try! String(contentsOfFile: native.eventLogPath, encoding: .utf8)
precondition(log.contains("test_event") && log.contains("测试"))
try! Data(repeating: 32, count: 1048576).write(to: URL(fileURLWithPath: native.eventLogPath))
native.logEvent("after_rotation")
precondition(FileManager.default.fileExists(atPath: native.eventLogPath + ".1"))
native.policyScriptPath = CommandLine.arguments[1]
native.configPath = CommandLine.arguments[2]
let config: [String: Any] = ["access_mode": "whitelist", "ip_check_mode": "http", "detect_ip_change": true,
                            "allowed_ips": [good, bad], "protection_enabled": true]
let initial = native.runPolicy(action: "evaluate", request: ["data": config, "ips": ["http": good]])
precondition(initial["state"] as? String == "allowed", "Native policy bridge did not allow first trusted exit")
let changed = native.runPolicy(action: "evaluate", request: ["data": config, "ips": ["http": bad]])
precondition(changed["state"] as? String == "blocked", "Native policy bridge allowed a whitelisted jump")
let returned = native.runPolicy(action: "evaluate", request: ["data": config, "ips": ["http": good]])
precondition(returned["state"] as? String == "blocked", "Jump latch did not survive returning to baseline")
let ackConfig = config.merging(["allowed_ips": [good]]) { _, new in new }
let ack = native.runPolicy(action: "ack-evaluate", request: ["data": ackConfig, "ips": ["http": bad], "expected_ips": ["http": bad]])
precondition(ack["state"] as? String == "blocked", "Acknowledgement bypassed whitelist")
precondition(ack["jump_acknowledged"] as? Bool == true, "Acknowledgement did not clear jump separately")
let ruleBlocked = native.runPolicy(action: "evaluate", request: ["data": ackConfig, "ips": ["http": bad]])
precondition(ruleBlocked["jump_latched"] as? Bool == false, "Whitelist denial incorrectly kept jump latch")
native.policyConfig = ["check_interval": 1.5]
native.configurePolling()
precondition(native.pollTimer!.timeInterval == 1.5)
let originalTimer = native.pollTimer
native.configurePolling()
precondition(native.pollTimer === originalTimer, "Unchanged interval should not reset the timer")
native.policyConfig["check_interval"] = 5
native.configurePolling()
precondition(!originalTimer!.isValid && native.pollTimer!.timeInterval == 5)
native.policyConfig["check_interval"] = true
precondition(native.checkInterval == 3, "Boolean interval must not be accepted")
native.pollTimer?.invalidate()
let firstDaemon = AppDelegate()
firstDaemon.configPath = CommandLine.arguments[2]
precondition(firstDaemon.acquireDaemonLock())
precondition(fcntl(firstDaemon.daemonLockFD, F_GETFD) & FD_CLOEXEC != 0, "Daemon lock leaked into child processes")
let secondDaemon = AppDelegate()
secondDaemon.configPath = firstDaemon.configPath
precondition(!secondDaemon.acquireDaemonLock(), "Two background guards acquired the same lock")
close(firstDaemon.daemonLockFD)
precondition(secondDaemon.acquireDaemonLock(), "Released daemon lock stayed stuck")
close(secondDaemon.daemonLockFD)
let cacheDirectory = URL(fileURLWithPath: CommandLine.arguments[2]).deletingLastPathComponent().appendingPathComponent("cache-test")
try! FileManager.default.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)
class CountingPolicy: AppDelegate {
    var calls = 0
    override func runPolicy(action: String, request: [String: Any]) -> [String: Any] {
        calls += 1
        return super.runPolicy(action: action, request: request)
    }
}
let cached = CountingPolicy()
cached.policyScriptPath = CommandLine.arguments[1]
cached.configPath = cacheDirectory.appendingPathComponent("config.json").path
for _ in 0..<3 {
    precondition(cached.evaluatePolicy(data: config, ips: ["http": good])["state"] as? String == "allowed")
}
precondition(cached.calls == 2, "Stable policy evaluations kept launching Python")
cached.cachedPolicyExpires = .distantPast
precondition(cached.evaluatePolicy(data: config, ips: ["http": good])["state"] as? String == "allowed")
precondition(cached.calls == 3, "Expired policy result was reused")
cached.cachedPolicyCreated = .distantFuture
_ = cached.evaluatePolicy(data: config, ips: ["http": good])
precondition(cached.calls == 4, "Clock rollback reused a future policy result")
let changedConfig = config.merging(["allowed_ips": [bad]]) { _, new in new }
precondition(cached.evaluatePolicy(data: changedConfig, ips: ["http": good])["state"] as? String == "blocked")
precondition(cached.calls == 5, "Rule changes reused a previous allow")
_ = cached.evaluatePolicy(data: changedConfig, ips: ["http": good])
precondition(cached.calls == 5, "Stable whitelist denials kept launching Python")
_ = cached.runPolicy(action: "ack-evaluate", request: ["data": config, "ips": ["http": bad], "expected_ips": ["http": bad]])
precondition(cached.evaluatePolicy(data: config, ips: ["http": good])["state"] as? String == "blocked", "External state change reused an allow")
cached.headless = true
cached.startBlinking()
cached.stopBlinking()
precondition(cached.blinkTimer == nil && cached.statusItem == nil)
class RepairProbe: AppDelegate {
    var calls = 0
    var succeeds = false
    override func runHelper(_ cmd: String, _ a1: String, _ a2: String) -> Process? {
        calls += 1
        guard succeeds else { return nil }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try! process.run()
        return process
    }
}
let repair = RepairProbe()
repair.configPath = CommandLine.arguments[2]
repair.runIntegrityRepair()
repair.runIntegrityRepair()
precondition(repair.calls == 2, "Failed repair was cached")
repair.succeeds = true
repair.runIntegrityRepair()
repair.runIntegrityRepair()
precondition(repair.calls == 3, "Unchanged integrity inputs kept spawning helpers")
class ScoredPolicy: AppDelegate {
    let fetched = Date().timeIntervalSince1970
    override func runPolicy(action: String, request: [String: Any]) -> [String: Any] {
        return ["state": "allowed", "scores": ["203.0.113.10": ["score": 10, "cached": false, "fetched_at": fetched]]]
    }
}
let scored = ScoredPolicy()
scored.configPath = cacheDirectory.appendingPathComponent("score/config.json").path
let riskConfig: [String: Any] = ["access_mode": "risk", "risk_cache_ttl": 10]
_ = scored.evaluatePolicy(data: riskConfig, ips: ["http": good])
precondition(abs(scored.cachedPolicyExpires.timeIntervalSince1970 - scored.fetched - 10) < 0.01, "Risk cache outlived its score TTL")
let reused = scored.evaluatePolicy(data: riskConfig, ips: ["http": good])
precondition((reused["scores"] as? [String: [String: Any]])?[good]?["cached"] as? Bool == true)
class PartialRiskFailure: AppDelegate {
    var calls = 0
    override func runPolicy(action: String, request: [String: Any]) -> [String: Any] {
        calls += 1
        return ["state": "blocked", "reason": "未取得有效风险评分，暂不放行",
                "scores": ["203.0.113.10": ["score": 10, "cached": true, "fetched_at": Date().timeIntervalSince1970]]]
    }
}
let partial = PartialRiskFailure()
partial.configPath = cacheDirectory.appendingPathComponent("partial/config.json").path
for _ in 0..<2 { _ = partial.evaluatePolicy(data: ["access_mode": "risk"], ips: ["http": good, "stun": bad]) }
precondition(partial.calls == 2, "Partial risk lookup failure was cached past the provider retry window")

precondition(AppDelegate.isIPAllowed("2001:db8::1", allowedList: ["2001:db8::/32"]))
precondition(AppDelegate.isIPAllowed("2001:db8::1", allowedList: ["2001:0db8:0000:0000:0000:0000:0000:0001"]))
precondition(!AppDelegate.isIPAllowed("1.2.3.4", allowedList: ["1.bad.2.3.4/32"]))
let transaction: [UInt8] = Array(0..<12)
let packet: [UInt8] = [1,1,0,12,0x21,0x12,0xa4,0x42] + transaction + [0,1,0,8,0,1,1,0xbb,203,0,113,10]
precondition(AppDelegate.parseStun(packet, transactionID: transaction) == good)
precondition(AppDelegate.parseStun(packet, transactionID: Array(repeating: 0, count: 12)) == nil)
precondition(AppDelegate.parseStun(Array(packet.dropLast()), transactionID: transaction) == nil)
class EnforcementProbe: AppDelegate {
    var succeeds = false
    var hostCalls = 0
    override func hostsDrifted() -> Bool { false }
    override func killDesktopIfRunning() -> Bool { false }
    override func helperSucceeded(_ cmd: String, _ a1: String, _ a2: String) -> Bool {
        if cmd == "sync_hosts" { hostCalls += 1 }
        return succeeds
    }
}
let enforcement = EnforcementProbe()
enforcement.eventLogPath = native.eventLogPath
enforcement.apply(from: .offline, to: .allowed(ip: good))
enforcement.apply(from: .offline, to: .allowed(ip: good))
precondition(enforcement.hostCalls == 2 && !enforcement.enforcementConfirmed, "Failed system operation was cached as applied")
enforcement.succeeds = true
enforcement.apply(from: .offline, to: .allowed(ip: good))
enforcement.apply(from: .offline, to: .allowed(ip: good))
precondition(enforcement.hostCalls == 3 && enforcement.enforcementConfirmed, "Successful operations repeated at every poll")
try! JSONSerialization.data(withJSONObject: ["protection_enabled": false, "allowed_ips": [good]]).write(to: URL(fileURLWithPath: native.configPath))
native.loadConfig()
precondition(native.configIsValid && !native.protectionEnabled)
try! JSONSerialization.data(withJSONObject: ["protection_enabled": 0, "allowed_ips": [good]]).write(to: URL(fileURLWithPath: native.configPath))
native.loadConfig()
precondition(!native.configIsValid && native.protectionEnabled, "Numeric zero disabled protection")
try! Data("{broken".utf8).write(to: URL(fileURLWithPath: native.configPath))
native.loadConfig()
precondition(!native.configIsValid && native.allowedIPs.isEmpty && native.protectionEnabled, "Corrupt config retained a previous allow")


class TransactionProbe: EnforcementProbe {
    var invalidateOnProbe = false
    override func detectExits(mode: String) -> [String: String] {
        if invalidateOnProbe { invalidateVerification(); invalidateOnProbe = false }
        return ["http": "203.0.113.10"]
    }
}
let transactionProbe = TransactionProbe()
transactionProbe.configPath = cacheDirectory.appendingPathComponent("transaction.json").path
transactionProbe.policyScriptPath = native.policyScriptPath
transactionProbe.eventLogPath = native.eventLogPath
transactionProbe.succeeds = true
transactionProbe.headless = true
try! Data("{broken".utf8).write(to: URL(fileURLWithPath: transactionProbe.configPath))
transactionProbe.performCheck()
precondition(!transactionProbe.recheckQueued, "A corrupt configuration caused an unbounded recheck loop")
try! JSONSerialization.data(withJSONObject: ["allowed_ips": [good], "ip_check_mode": "http"]).write(to: URL(fileURLWithPath: transactionProbe.configPath))
transactionProbe.invalidateOnProbe = true
transactionProbe.performCheck()
precondition(transactionProbe.state == .offline && !transactionProbe.enforcementConfirmed && transactionProbe.recheckQueued, "In-flight network change published a stale allow")
transactionProbe.recheckQueued = false
transactionProbe.performCheck()
precondition(transactionProbe.state == .allowed(ip: good) && transactionProbe.enforcementConfirmed)
let noisy = cacheDirectory.appendingPathComponent("large-policy.py")
try! Data("import sys,json\njson.load(sys.stdin)\nprint(json.dumps({'valid':True,'padding':'x'*200000}))\n".utf8).write(to: noisy)
transactionProbe.policyScriptPath = noisy.path
let bridgeStart = Date()
precondition(transactionProbe.runPolicy(action: "validate", request: ["data": [:]])["valid"] as? Bool == true)
precondition(Date().timeIntervalSince(bridgeStart) < 5, "Policy pipe blocked before reading a large valid result")


let fifo = cacheDirectory.appendingPathComponent("state-fifo")
precondition(mkfifo(fifo.path, 0o600) == 0)
let fifoStart = Date()
precondition((try? native.boundedData(at: fifo)) == nil)
precondition(Date().timeIntervalSince(fifoStart) < 0.5, "A named pipe blocked the guard")
let settingsLock = AppDelegate()
settingsLock.configPath = firstDaemon.configPath
precondition(firstDaemon.acquireDaemonLock())
precondition(settingsLock.acquireDaemonLock(name: "settings.lock"), "A running daemon blocked the settings window")
close(settingsLock.daemonLockFD)
close(firstDaemon.daemonLockFD)

print("Swift both verdict matrix passed")
'''
        with tempfile.TemporaryDirectory() as d:
            main = Path(d) / 'main.swift'
            executable = Path(d) / 'check'
            main.write_text(source + harness)
            subprocess.run(['swiftc', str(main), '-o', str(executable)], check=True, capture_output=True, text=True)
            result = subprocess.run([str(executable), str(Path(__file__).resolve().parents[1] / "src/policy_cli.py"), str(Path(d) / "config.json")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Swift both verdict matrix passed', result.stdout)
