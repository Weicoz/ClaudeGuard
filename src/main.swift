import AppKit
import Foundation
import SystemConfiguration
import Network

// ClaudeGuard background guard; AppKit settings and alerts open on demand.
//
// State machine: compute one GuardState, touch the system only on transitions
// (blocking/unblocking domains, killing the app, alerting) — never on every
// poll. Owns two enforcement surfaces: the Claude Desktop app (force-quit +
// alert) and the claude/anthropic domains (/etc/hosts + pf). The `claude` CLI
// enforces itself from src/cli_wrapper.py — a background daemon has no terminal.

enum GuardState: Equatable {
    case disabled              // protection off
    case offline               // no internet — can't verify
    case allowed(ip: String)   // public IP is whitelisted
    case blocked(ip: String)   // online, IP not whitelisted

    // Fail closed: domains open only on a confirmed good IP; offline blocks too.
    var domainsShouldBeBlocked: Bool {
        switch self {
        case .allowed, .disabled: return false
        case .blocked, .offline:  return true
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    var headless = false
    var settingsOnly = false
    var alertOnly = false
    var settingsBusy = false
    var daemonLockFD: Int32 = -1
    static let recheckNotification = Notification.Name("com.claudeguard.recheck")
    var statusItem: NSStatusItem!
    var menu: NSMenu!

    var state: GuardState = .offline
    var currentIP: String = "…"
    var protectionEnabled: Bool = true
    var blockAutoUpdates: Bool = true
    var modelOverrideEnabled: Bool = false
    var defaultModel: String = "claude-opus-4-8"
    var allowedIPs: [String] = []
    var ipCheckMode: String = "both"
    var verdictIPCheckMode: String = "both"
    var detectedIPs: [String: String] = [:]
    var policyConfig: [String: Any] = [:]
    var verdictPolicyConfig: [String: Any] = [:]
    var policyReason: String = ""
    var policyScriptPath = NSString(string: "~/.local/share/ClaudeGuard/src/policy_cli.py").expandingTildeInPath
    var riskScores: [String: Any] = [:]
    var eventLogPath = NSString(string: "~/.config/claudeguard/events.jsonl").expandingTildeInPath
    private let eventLogLock = NSLock()

    func logEvent(_ event: String, fields: [String: Any] = [:]) {
        eventLogLock.lock()
        defer { eventLogLock.unlock() }
        let record = fields.merging(["time": ISO8601DateFormatter().string(from: Date()), "event": event]) { _, new in new }
        guard var data = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]) else { return }
        data.append(10)
        let path = URL(fileURLWithPath: eventLogPath)
        let manager = FileManager.default
        do {
            try manager.createDirectory(at: path.deletingLastPathComponent(), withIntermediateDirectories: true)
            let size = (try? manager.attributesOfItem(atPath: path.path)[.size] as? NSNumber)?.intValue ?? 0
            if size + data.count > 1048576 {
                let backup = path.appendingPathExtension("1")
                if manager.fileExists(atPath: backup.path) { try manager.removeItem(at: backup) }
                if manager.fileExists(atPath: path.path) { try manager.moveItem(at: path, to: backup) }
            }
            if !manager.fileExists(atPath: path.path) {
                manager.createFile(atPath: path.path, contents: nil, attributes: [.posixPermissions: 0o600])
            }
            let handle = try FileHandle(forWritingTo: path)
            defer { handle.closeFile() }
            handle.seekToEndOfFile()
            handle.write(data)
        } catch {
            fputs("ClaudeGuard: 无法写入检测日志\n", stderr)
        }
    }

    var jumpBlocked = false
    var cachedPolicyRequest: Data?
    var cachedPolicyState: Data?
    var cachedPolicyOutcome: [String: Any]?
    var cachedPolicyExpires = Date.distantPast
    var cachedPolicyCreated = Date.distantFuture
    var lastIntegritySignature: [String]?
    var integrityRunning = false
    var pollTimer: Timer?
    var scheduledPollInterval: Double = 0

    var checkInterval: Double {
        guard let raw = policyConfig["check_interval"] as? NSNumber,
              CFGetTypeID(raw) != CFBooleanGetTypeID(), raw.doubleValue.isFinite,
              (1...60).contains(raw.doubleValue) else { return 3 }
        return raw.doubleValue
    }

    var usesAdvancedPolicy: Bool {
        let access = policyConfig["access_mode"] == nil ? "whitelist" : (policyConfig["access_mode"] as? String ?? "invalid")
        let rawJump = policyConfig["detect_ip_change"]
        let jump = rawJump as? Bool ?? (rawJump != nil)
        let rawAllow = policyConfig["allow_unknown_ip"]
        let allowUnknown = rawAllow as? Bool ?? (rawAllow != nil)
        return access != "whitelist" || jump || allowUnknown
    }
    var verdictAllowedIPs: [String] = []

    var dynamicStore: SCDynamicStore?
    var pathMonitor: NWPathMonitor?
    // Usable network route, from NWPathMonitor — lets us declare "offline" the
    // instant Wi-Fi drops instead of waiting for HTTP timeouts.
    var hasNetworkPath: Bool = true
    var blinkTimer: Timer?
    var blinkState: Bool = false
    var displayedSymbol: String?
    // Serialize + coalesce rechecks. A plain "drop if busy" lock loses the
    // network event that arrives mid-check — the classic cause of a boot (or a
    // VPN handoff) that latches on offline/blocked until a reboot. Instead:
    // while a check runs, fold new requests into a flag and run one more pass
    // when it finishes, so the newest event is always acted on.
    let checkLock = NSLock()
    var checkRunning = false
    var recheckQueued = false
    var configPath = NSString(string: "~/.config/claudeguard/config.json").expandingTildeInPath

    // Last enforcement pushed to the system, to skip redundant work. nil = never
    // applied, force a first apply.
    var lastAppliedDomainsBlocked: Bool? = nil
    var lastAppliedBlockUpdates: Bool? = nil
    // Alerted once for the current blocked episode (reset on leaving blocked).
    var hasAlertedThisBlock: Bool = false

    // MARK: - Lifecycle

    func applicationDidFinishLaunching(_ notification: Notification) {
        if alertOnly {
            showBlockedAlert(reason: CommandLine.arguments.last ?? "出口未通过检查")
            return
        }
        // Single-instance guard. LaunchAgent runs the bare binary, Launchpad
        // runs the .app — match both names and the bundle id.
        let myPID = getpid()
        for app in NSWorkspace.shared.runningApplications where app.processIdentifier != myPID {
            let name = app.localizedName ?? ""
            if name == "ClaudeGuardMenuBar" || name == "ClaudeGuard" || app.bundleIdentifier == "com.claudeguard.app" {
                NSApplication.shared.terminate(nil)
                return
            }
        }

        if let iconPath = Bundle.main.path(forResource: "AppIcon", ofType: "icns"),
           let iconImage = NSImage(contentsOfFile: iconPath) {
            NSApplication.shared.applicationIconImage = iconImage
        }

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu

        loadConfig()
        if settingsOnly {
            let agent = Process()
            agent.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            agent.arguments = ["kickstart", "gui/\(getuid())/com.claudeguard.daemon"]
            agent.standardOutput = FileHandle.nullDevice
            agent.standardError = FileHandle.nullDevice
            var started = false
            do { try agent.run(); agent.waitUntilExit(); started = agent.terminationStatus == 0 } catch {}
            if !started {
                let daemon = Process()
                daemon.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
                daemon.arguments = ["--daemon"]
                try? daemon.run()
            }
            refreshSettingsState()
            Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.refreshSettingsState() }
            DispatchQueue.main.async { self.statusItem.button?.performClick(nil) }
            return
        }
        startGuard()
    }

    func acquireDaemonLock() -> Bool {
        let directory = URL(fileURLWithPath: configPath).deletingLastPathComponent()
        do { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true) } catch { return false }
        daemonLockFD = open(directory.appendingPathComponent("daemon.lock").path, O_CREAT | O_RDWR | O_CLOEXEC, 0o600)
        guard daemonLockFD >= 0 else { return false }
        if flock(daemonLockFD, LOCK_EX | LOCK_NB) == 0 { return true }
        close(daemonLockFD)
        daemonLockFD = -1
        return false
    }

    func startGuard() {
        loadConfig()
        logEvent("guard_started", fields: ["mode": ipCheckMode, "check_interval": checkInterval])
        if !headless { rebuildMenu() }

        setupAppLaunchInterceptor()

        // Bring the network monitors up first so no early Wi-Fi/VPN transition
        // is missed, then verify. State is unknown until the first check returns.
        setupPathMonitor()      // connectivity up/down
        setupNetworkObserver()  // VPN/route/IP changes while online
        setupWakeObserver()     // re-verify after the Mac wakes from sleep
        DistributedNotificationCenter.default().addObserver(forName: Self.recheckNotification, object: nil, queue: .main) { [weak self] _ in
            self?.recheckAsync()
        }

        startBlinking()
        DispatchQueue.global(qos: .userInitiated).async { self.recheck() }

        // Fallback poll — catches a public-IP change with no local network event,
        // and (paired with the coalescing recheck) guarantees the daemon
        // self-heals from a bad boot within one interval instead of needing a
        // reboot. .utility so the OS won't suspend it the way it can .background.
        configurePolling()

        // Hook self-heal. Separate from recheck() because it guards a different
        // failure: not a network change, but Claude being reinstalled underneath
        // us and quietly detaching the guard.
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2.0) { self.runIntegrityRepair() }
        Timer.scheduledTimer(withTimeInterval: 60.0, repeats: true) { _ in
            DispatchQueue.global(qos: .utility).async { self.runIntegrityRepair() }
        }
    }

    func configurePolling() {
        guard !settingsOnly else { return }
        let interval = checkInterval
        guard pollTimer == nil || scheduledPollInterval != interval else { return }
        pollTimer?.invalidate()
        scheduledPollInterval = interval
        pollTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            DispatchQueue.global(qos: .utility).async {
                guard let self = self else { return }
                self.checkLock.lock()
                let busy = self.checkRunning
                self.checkLock.unlock()
                // Slow checks skip timer ticks rather than build a backlog.
                if !busy { self.recheck() }
            }
        }
    }

    func runIntegrityRepair() {
        // shortcut: new installs outside watched paths need doctor; add Spotlight events if this becomes common.
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let paths = [configPath, home + "/.local/bin/claude", "/opt/homebrew/bin/claude", "/usr/local/bin/claude",
                     home + "/.local/bin", "/opt/homebrew/bin", "/usr/local/bin",
                     home + "/.local/share/claude/versions", "/opt/homebrew/Caskroom/claude-code", "/usr/local/Caskroom/claude-code",
                     "/Applications", home + "/Applications",
                     policyConfig["real_claude_cli_path"] as? String ?? "", policyConfig["real_claude_app_path"] as? String ?? ""]
        let signature = paths.map { path -> String in
            let attributes = (try? FileManager.default.attributesOfItem(atPath: path)) ?? [:]
            let target = (try? FileManager.default.destinationOfSymbolicLink(atPath: path)) ?? ""
            return "\(path):\(attributes[.modificationDate] ?? "missing"):\(attributes[.systemFileNumber] ?? "missing"):\(attributes[.posixPermissions] ?? "missing"):\(target)"
        }
        guard signature != lastIntegritySignature, !integrityRunning else { return }
        integrityRunning = true
        defer { integrityRunning = false }
        if let task = runHelper("integrity", "", "") {
            task.waitUntilExit()
            if task.terminationStatus == 0 { lastIntegritySignature = signature }
        }
    }

    /// True when /etc/hosts no longer matches what we last applied — an OS
    /// update, another tool or a manual edit reverted our block.
    func hostsDrifted() -> Bool {
        guard let wantDomains = lastAppliedDomainsBlocked,
              let wantUpdates = lastAppliedBlockUpdates,
              let content = try? String(contentsOfFile: "/etc/hosts", encoding: .utf8)
        else { return false }
        let hasDomains = content.contains("# BEGIN CLAUDEGUARD BLOCKS")
        let hasUpdates = content.contains("# BEGIN CLAUDEGUARD UPDATE BLOCKS")
        return hasDomains != wantDomains || hasUpdates != wantUpdates
    }

    /// Claude Desktop, matched by bundle-id *prefix* — the exact id has already
    /// changed once (claudefor-mac → claudefordesktop). The name is only a
    /// fallback: it's localized, so it can't be the primary test.
    static func isClaudeDesktop(_ app: NSRunningApplication) -> Bool {
        if let bundleID = app.bundleIdentifier {
            if bundleID.hasPrefix("com.claudeguard") { return false }   // never ourselves
            if bundleID.hasPrefix("com.anthropic.claude") { return true }
        }
        return (app.localizedName ?? "") == "Claude"
    }

    // MARK: - Connectivity monitor (Network framework)

    func setupPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            let satisfied = (path.status == .satisfied)
            let changed = (self.hasNetworkPath != satisfied)
            self.hasNetworkPath = satisfied
            // Connectivity flipped — re-verify. Down → recheck() declares offline
            // instantly; up → recheck() runs the IP check.
            if changed { self.startBlinking() }
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + (satisfied ? 0.4 : 0.0)) {
                self.recheck()
            }
        }
        monitor.start(queue: DispatchQueue(label: "com.claudeguard.path"))
        self.pathMonitor = monitor
    }

    // MARK: - Real-time network observer

    func setupNetworkObserver() {
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)

        let callback: SCDynamicStoreCallBack = { (_, _, info) in
            guard let info = info else { return }
            let me = Unmanaged<AppDelegate>.fromOpaque(info).takeUnretainedValue()
            // Network event fired — don't act blindly, just re-verify once it
            // settles; recheck() decides.
            me.startBlinking()
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 0.3) { me.recheck() }
        }

        guard let store = SCDynamicStoreCreate(kCFAllocatorDefault, "com.claudeguard.app" as CFString, callback, &context) else { return }
        self.dynamicStore = store
        let patterns = [
            "State:/Network/Global/IPv4",
            "State:/Network/Global/IPv6",
            "State:/Network/Interface/.*",
            "State:/Network/Service/.*"
        ] as CFArray
        SCDynamicStoreSetNotificationKeys(store, nil, patterns)
        if let src = SCDynamicStoreCreateRunLoopSource(kCFAllocatorDefault, store, 0) {
            CFRunLoopAddSource(CFRunLoopGetCurrent(), src, .defaultMode)
        }
    }

    // MARK: - Wake-from-sleep

    /// After the Mac wakes, the route and VPN re-establish over several seconds
    /// and NWPathMonitor may not emit a clean transition. Fire a few staggered
    /// rechecks so we never sit on a stale pre-sleep verdict.
    func setupWakeObserver() {
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            guard let self = self else { return }
            self.startBlinking()
            for delay in [0.5, 3.0, 8.0] {
                DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + delay) {
                    self.recheck()
                }
            }
        }
    }

    // MARK: - Desktop app launch interceptor

    func setupAppLaunchInterceptor() {
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didLaunchApplicationNotification, object: nil, queue: .main) { [weak self] note in
            guard let self = self else { return }
            guard let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication else { return }
            if Self.isClaudeDesktop(app) {
                guard self.protectionEnabled else { return }
                // Fail closed on a fresh launch, even offline: an unverified
                // session must not start.
                if case .allowed = self.state { return }
                self.logEvent("desktop_launch_blocked", fields: ["reason": self.policyReason, "ip": self.currentIP])
                app.forceTerminate()
                self.runPkill(target: "Claude.app")
                let reason: String
                switch self.state {
                case .offline: reason = "暂时无法确认出口 IP，请检查网络和代理设置。"
                default:       reason = "当前出口未通过白名单检查：\(self.currentIP)。"
                }
                self.showBlockedAlert(reason: self.policyReason.isEmpty ? reason : self.policyReason)
            }
        }
    }

    // MARK: - Core check

    func recheck() {
        // Coalescing gate: at most one check runs at a time; a request that
        // arrives while one is in flight sets a flag so exactly one more pass
        // runs afterwards. No network event is ever silently dropped, and two
        // quick config toggles can't leave enforcement out of sync.
        checkLock.lock()
        if checkRunning {
            recheckQueued = true
            checkLock.unlock()
            return
        }
        checkRunning = true
        checkLock.unlock()

        while true {
            checkLock.lock(); recheckQueued = false; checkLock.unlock()

            autoreleasepool { performCheck() }

            checkLock.lock()
            if recheckQueued { checkLock.unlock(); continue }
            checkRunning = false
            checkLock.unlock()
            break
        }
        stopBlinking()
    }

    /// One verification pass: resolve the public IP, fold it into a GuardState,
    /// push enforcement on transitions, publish the verdict.
    func performCheck() {
        loadConfig()
        let previousReason = policyReason
        let checkedMode = ipCheckMode
        let checkedIPs = allowedIPs
        let checkedPolicy = policyConfig
        let advancedPolicy = usesAdvancedPolicy
        policyReason = ""
        riskScores = [:]
        jumpBlocked = false

        detectedIPs = [:]
        let newState: GuardState
        if !protectionEnabled {
            newState = .disabled
        } else {
            let results = detectExits(mode: checkedMode)
            detectedIPs = results
            if advancedPolicy {
                let outcome = evaluatePolicy(data: checkedPolicy, ips: results)
                policyReason = outcome["reason"] as? String ?? "策略检查失败，暂不放行"
                riskScores = outcome["scores"] as? [String: Any] ?? [:]
                jumpBlocked = outcome["jump_latched"] as? Bool == true
                currentIP = checkedMode == "both" ? Self.describeBoth(results) : (results[checkedMode] ?? "No Internet")
                if outcome["state"] as? String == "allowed" {
                    newState = .allowed(ip: currentIP)
                } else {
                    newState = .blocked(ip: currentIP)
                }
            } else if checkedMode == "both" {
                currentIP = Self.describeBoth(results)
                newState = Self.bothState(results, allowedList: checkedIPs)
            } else if let ip = results[checkedMode] {
                currentIP = ip
                newState = Self.isIPAllowed(ip, allowedList: checkedIPs) ? .allowed(ip: ip) : .blocked(ip: ip)
            } else {
                currentIP = "No Internet"
                newState = .offline
            }
            if !results.isEmpty { hasNetworkPath = true }

        }

        let previous = state
        state = newState
        if previous != newState || previousReason != policyReason {
            logEvent("verdict_changed", fields: ["state": statusText(), "mode": checkedMode,
                     "detected_ips": detectedIPs, "reason": policyReason, "jump_latched": jumpBlocked])
        }
        verdictIPCheckMode = checkedMode
        verdictAllowedIPs = checkedIPs
        verdictPolicyConfig = checkedPolicy
        apply(from: previous, to: newState)
        writeStateFile()  // publish verdict for the CLI wrapper

        DispatchQueue.main.async { self.configurePolling() }
    }

    /// Publishes the verdict to state.json (single source of truth for the CLI
    /// wrapper). Written atomically each recheck; a stale file signals the
    /// daemon is down and the wrapper should fall back to its own check.
    func writeStateFile() {
        let stateStr: String
        switch state {
        case .allowed:  stateStr = "allowed"
        case .blocked:  stateStr = "blocked"
        case .offline:  stateStr = "offline"
        case .disabled: stateStr = "disabled"
        }
        let dict: [String: Any] = [
            "state": stateStr,
            "ip": currentIP,
            "detected_ips": detectedIPs,
            "access_mode": verdictPolicyConfig["access_mode"] ?? "whitelist",
            "detect_ip_change": verdictPolicyConfig["detect_ip_change"] ?? false,
            "allow_unknown_ip": verdictPolicyConfig["allow_unknown_ip"] ?? false,
            "reason": policyReason,
            "scores": riskScores,
            "jump_latched": jumpBlocked,
            "ip_check_mode": verdictIPCheckMode,
            "check_interval": checkInterval,
            "http_proxy": policyConfig["http_proxy"] as? String ?? "",
            "allowed_ips": verdictAllowedIPs,
            "protection_enabled": stateStr != "disabled",
            "updated_at": Date().timeIntervalSince1970
        ]
        let path = NSString(string: "~/.config/claudeguard/state.json").expandingTildeInPath
        if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted]) {
            try? data.write(to: URL(fileURLWithPath: path), options: .atomic)
        }
    }

    /// The only place that touches the system. Each piece runs only when its
    /// input actually changed.
    func apply(from previous: GuardState, to new: GuardState) {
        // Transition-only enforcement assumes nothing else edits /etc/hosts;
        // drift means "pretend we never applied anything" and re-apply.
        if hostsDrifted() {
            lastAppliedDomainsBlocked = nil
            lastAppliedBlockUpdates = nil
        }

        // Domains: /etc/hosts holds both claude-domain and update-domain blocks,
        // so rewrite when either flips.
        let wantBlocked = new.domainsShouldBeBlocked
        let domainsChanged = (lastAppliedDomainsBlocked != wantBlocked)
        let updatesChanged = (lastAppliedBlockUpdates != blockAutoUpdates)

        if domainsChanged || updatesChanged {
            lastAppliedDomainsBlocked = wantBlocked
            runHelper("sync_hosts", wantBlocked ? "true" : "false", String(blockAutoUpdates))
        }

        // Auto-update lock (chmod/chflags) — only on change.
        if updatesChanged {
            lastAppliedBlockUpdates = blockAutoUpdates
            runHelper("sync_updates", String(blockAutoUpdates), "")
        }

        // Desktop app kill + alert.
        switch new {
        case .blocked:
            let killed = killDesktopIfRunning()
            if killed { logEvent("desktop_closed", fields: ["reason": policyReason, "ip": currentIP]) }
            if killed && !hasAlertedThisBlock {   // alert once per blocked episode
                hasAlertedThisBlock = true
                showBlockedAlert(reason: policyReason.isEmpty ? "当前出口未通过白名单检查：\(currentIP)。" : policyReason)
            }
        case .allowed, .disabled, .offline:
            // offline: don't kill a running app — nothing to protect against.
            hasAlertedThisBlock = false
        }
        _ = previous
    }

    // MARK: - IP fetch (STUN-first, HTTP fallback, raced)

    let stunServers: [(String, UInt16)] = [
        ("stun.l.google.com", 19302),
        ("stun1.l.google.com", 19302),
        ("stun.cloudflare.com", 3478)
    ]
    var httpServices = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/ip",
        "https://ipinfo.io/ip",
        "https://icanhazip.com",
        "https://api.myip.com"
    ]
    var httpSession: URLSession?
    var httpSessionProxy = ""
    var httpSessionDeadline: TimeInterval = 0
    var preferredHTTPService: String?

    func sessionForHTTPProbe(deadline: TimeInterval) -> URLSession {
        let address = policyConfig["http_proxy"] as? String ?? ""
        if let session = httpSession, httpSessionProxy == address, httpSessionDeadline == deadline { return session }
        httpSession?.invalidateAndCancel()
        let cfg = URLSessionConfiguration.ephemeral
        cfg.urlCache = nil
        cfg.httpCookieStorage = nil
        cfg.urlCredentialStorage = nil
        cfg.httpShouldSetCookies = false
        if !address.isEmpty, let proxy = URLComponents(string: address), let host = proxy.host, let port = proxy.port {
            cfg.connectionProxyDictionary = ["HTTPEnable": 1, "HTTPProxy": host, "HTTPPort": port,
                                             "HTTPSEnable": 1, "HTTPSProxy": host, "HTTPSPort": port]
        }
        cfg.timeoutIntervalForRequest = deadline
        cfg.timeoutIntervalForResource = deadline
        let session = URLSession(configuration: cfg)
        httpSession = session
        httpSessionProxy = address
        httpSessionDeadline = deadline
        return session
    }

    static func describeBoth(_ ips: [String: String]) -> String {
        return "HTTP: \(ips["http"] ?? "未获取"); STUN: \(ips["stun"] ?? "未获取")"
    }

    static func bothState(_ ips: [String: String], allowedList: [String]) -> GuardState {
        let display = describeBoth(ips)
        // A known unlisted exit blocks even if the other transport timed out.
        if ["http", "stun"].contains(where: { mode in
            guard let ip = ips[mode] else { return false }
            return !isIPAllowed(ip, allowedList: allowedList)
        }) { return .blocked(ip: display) }
        guard ips["http"] != nil, ips["stun"] != nil else { return .offline }
        return .allowed(ip: display)
    }

    /// Resolve one transport. Both-mode callers wait for two independent results.
    func detectExits(mode: String) -> [String: String] {
        let modes = mode == "both" ? ["http", "stun"] : [mode]
        let group = DispatchGroup()
        let lock = NSLock()
        var results: [String: String] = [:]
        for transport in modes {
            group.enter()
            DispatchQueue.global(qos: .utility).async {
                let ip = self.resolvePublicIP(deadline: 2.0, mode: transport)
                lock.lock()
                if let ip = ip { results[transport] = ip }
                lock.unlock()
                group.leave()
            }
        }
        group.wait()
        return results
    }

    func resolvePublicIP(deadline: TimeInterval = 2.0, mode selectedMode: String? = nil) -> String? {
        let mode = selectedMode ?? ipCheckMode
        guard ["http", "stun"].contains(mode) else { return nil }
        let sem = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var result: String? = nil
        var winningService: String?
        var diagnostics: [String: [String: Any]] = [:]
        let started = Date()
        func offer(_ ip: String?, service: String? = nil) {
            guard let ip = ip, !ip.isEmpty else { return }
            lock.lock()
            let first = (result == nil)
            if first { result = ip; winningService = service }
            lock.unlock()
            if first { sem.signal() }
        }

        // STUN (fast path)
        var conns: [NWConnection] = []
        for (host, port) in (mode == "http" ? [] : stunServers) {
            if let c = stunQuery(host: host, port: port, completion: { offer($0) }) {
                conns.append(c)
            }
        }

        var tasks: [URLSessionDataTask] = []
        var resolved = false
        if mode == "http" {
            let session = sessionForHTTPProbe(deadline: deadline)
            let services = httpServices.sorted { $0 == preferredHTTPService && $1 != preferredHTTPService }
            func startHTTP(_ service: String) {
                guard let url = URL(string: service) else { return }
                var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: deadline)
                req.setValue("ClaudeGuard/1.0", forHTTPHeaderField: "User-Agent")
                // A fresh connection must observe the current route, including VPN changes.
                req.setValue("close", forHTTPHeaderField: "Connection")
                let task = session.dataTask(with: req) { data, response, err in
                    let code = (response as? HTTPURLResponse)?.statusCode ?? 0
                    let parsed = Self.parseHTTPIP(data)
                    var detail: [String: Any] = ["http_status": code, "elapsed_ms": Int(Date().timeIntervalSince(started) * 1000)]
                    if let error = err as NSError? {
                        detail["error_domain"] = error.domain
                        detail["error_code"] = error.code
                    } else if !(200...299).contains(code) {
                        detail["error"] = "HTTP 状态异常"
                    } else if parsed == nil {
                        detail["error"] = "响应不含有效 IP"
                    }
                    lock.lock(); diagnostics[service] = detail; lock.unlock()
                    guard err == nil, (200...299).contains(code) else { return }
                    offer(parsed, service: service)
                }
                tasks.append(task)
                task.resume()
            }
            // Healthy polls need one request. Hedge slow/failing providers within the same deadline.
            if let first = services.first { startHTTP(first) }
            resolved = sem.wait(timeout: .now() + min(0.25, deadline / 4)) == .success
            if !resolved { services.dropFirst().forEach { startHTTP($0) } }
        }

        if !resolved { _ = sem.wait(timeout: .now() + max(0, deadline - Date().timeIntervalSince(started))) }
        conns.forEach { $0.cancel() }
        tasks.forEach { $0.cancel() }

        lock.lock(); let ip = result; let details = diagnostics; let winner = winningService; lock.unlock()
        if let winner = winner { preferredHTTPService = winner }
        if ip == nil {
            var fields: [String: Any] = ["mode": mode, "deadline_seconds": deadline, "elapsed_ms": Int(Date().timeIntervalSince(started) * 1000)]
            if mode == "http" {
                fields["services"] = Dictionary(uniqueKeysWithValues: httpServices.map { ($0, details[$0] ?? ["error": "截止时间内未返回"]) })
            }
            logEvent("probe_failed", fields: fields)
        }
        return ip
    }

    static func parseHTTPIP(_ data: Data?) -> String? {
        guard let data = data,
              let str = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !str.isEmpty else { return nil }
        let candidate: String
        if str.contains("{"), let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let ip = json["ip"] as? String {
            candidate = ip.trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            candidate = str
        }
        return IPv4Address(candidate) != nil || IPv6Address(candidate) != nil ? candidate : nil
    }

    /// Fires one STUN Binding Request over UDP and calls `completion` with the
    /// mapped public IP (or nil). Returns the live connection so the caller can
    /// cancel it. Non-blocking.
    func stunQuery(host: String, port: UInt16, completion: @escaping (String?) -> Void) -> NWConnection? {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { completion(nil); return nil }
        let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .udp)

        // STUN Binding Request: type 0x0001, length 0, magic cookie, 12-byte txid.
        var req = Data([0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42])
        for _ in 0..<12 { req.append(UInt8.random(in: 0...255)) }

        let lock = NSLock()
        var done = false
        func finish(_ ip: String?) {
            lock.lock()
            if done { lock.unlock(); return }
            done = true
            lock.unlock()
            completion(ip)
        }

        conn.stateUpdateHandler = { st in
            switch st {
            case .ready:
                conn.send(content: req, completion: .contentProcessed { err in
                    if err != nil { finish(nil) }
                })
                conn.receiveMessage { data, _, _, _ in
                    finish(data.flatMap { Self.parseStun([UInt8]($0)) })
                }
            case .failed, .cancelled:
                finish(nil)
                conn.stateUpdateHandler = nil
            default:
                break
            }
        }
        conn.start(queue: DispatchQueue(label: "com.claudeguard.stun"))
        return conn
    }

    /// Parses a STUN Binding Success Response, returning the IPv4 from the
    /// XOR-MAPPED-ADDRESS (0x0020) or plain MAPPED-ADDRESS (0x0001) attribute.
    static func parseStun(_ b: [UInt8]) -> String? {
        guard b.count >= 20, b[0] == 0x01, b[1] == 0x01 else { return nil } // 0x0101 success
        let msgLen = Int(b[2]) << 8 | Int(b[3])
        let cookie: [UInt8] = [0x21, 0x12, 0xA4, 0x42]
        var i = 20
        let end = min(20 + msgLen, b.count)
        while i + 4 <= end {
            let attrType = Int(b[i]) << 8 | Int(b[i + 1])
            let attrLen = Int(b[i + 2]) << 8 | Int(b[i + 3])
            let vs = i + 4
            if vs + attrLen > b.count { break }
            if (attrType == 0x0020 || attrType == 0x0001), attrLen >= 8, b[vs + 1] == 0x01 {
                let a0, a1, a2, a3: UInt8
                if attrType == 0x0020 { // XOR-MAPPED: address XOR'd with the magic cookie
                    a0 = b[vs + 4] ^ cookie[0]
                    a1 = b[vs + 5] ^ cookie[1]
                    a2 = b[vs + 6] ^ cookie[2]
                    a3 = b[vs + 7] ^ cookie[3]
                } else {
                    a0 = b[vs + 4]; a1 = b[vs + 5]; a2 = b[vs + 6]; a3 = b[vs + 7]
                }
                return "\(a0).\(a1).\(a2).\(a3)"
            }
            i = vs + attrLen
            if attrLen % 4 != 0 { i += 4 - (attrLen % 4) } // pad to 4-byte boundary
        }
        return nil
    }

    /// Matches an IP against exact entries or IPv4 CIDR ranges — mirrors
    /// ip_checker.py so the daemon and the CLI agree on what's whitelisted.
    static func isIPAllowed(_ ip: String, allowedList: [String]) -> Bool {
        for raw in allowedList {
            let entry = raw.trimmingCharacters(in: .whitespaces)
            if entry.isEmpty { continue }
            if entry == ip { return true }
            if entry.contains("/"), let ipv = ipv4ToUInt32(ip) {
                let parts = entry.split(separator: "/")
                if parts.count == 2, let net = ipv4ToUInt32(String(parts[0])), let bits = Int(parts[1]), (0...32).contains(bits) {
                    let mask: UInt32 = bits == 0 ? 0 : (~UInt32(0)) << (32 - bits)
                    if (ipv & mask) == (net & mask) { return true }
                }
            }
        }
        return false
    }

    static func ipv4ToUInt32(_ ip: String) -> UInt32? {
        let p = ip.split(separator: ".", omittingEmptySubsequences: false).compactMap { UInt32($0) }
        guard p.count == 4, p.allSatisfy({ $0 <= 255 }) else { return nil }
        return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]
    }

    // MARK: - Process control

    func runPkill(target: String) {
        let t1 = Process()
        t1.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        t1.arguments = ["-15", "-f", target]
        try? t1.run()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.15) {
            let t2 = Process()
            t2.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
            t2.arguments = ["-9", "-f", target]
            try? t2.run()
        }
    }

    @discardableResult
    func killDesktopIfRunning() -> Bool {
        let victims = NSWorkspace.shared.runningApplications.filter { Self.isClaudeDesktop($0) }
        guard !victims.isEmpty else { return false }
        // Terminate the matched processes directly (precise wherever the app was
        // installed); pkill is the second pass for helpers it spawns.
        victims.forEach { $0.forceTerminate() }
        runPkill(target: "Claude.app")
        return true
    }

    static func isClaudeCLIPath(_ path: String, command: String = "") -> Bool {
        let name = URL(fileURLWithPath: path).lastPathComponent.lowercased()
        if ["node", "node.exe"].contains(name) {
            let script = command.split(whereSeparator: { $0.isWhitespace }).dropFirst().first(where: { !$0.hasPrefix("-") }) ?? ""
            return script.contains("@anthropic-ai/claude-code/")
        }
        return ["claude", "claude.exe", "claude.orig", "claude.real"].contains(name)
            || path.hasPrefix(NSHomeDirectory() + "/.local/share/claude/versions/")
    }

    static func executablePath(_ pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4096)
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        return String(cString: buffer)
    }

    func closeClaudeSessions(dryRun: Bool) -> Int32 {
        let desktop = NSWorkspace.shared.runningApplications.filter { Self.isClaudeDesktop($0) }
        let desktopIDs = Set(desktop.map { $0.processIdentifier })
        var targets: [pid_t: String] = [:]
        for app in desktop { targets[app.processIdentifier] = app.executableURL?.path ?? "Claude Desktop" }
        let query = Process()
        query.executableURL = URL(fileURLWithPath: "/bin/ps")
        query.arguments = ["-axo", "pid=,uid=,command="]
        let output = Pipe()
        query.standardOutput = output
        do {
            try query.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            query.waitUntilExit()
            for line in (String(data: data, encoding: .utf8) ?? "").split(separator: "\n") {
                let fields = line.split(maxSplits: 2, whereSeparator: { $0.isWhitespace })
                guard fields.count == 3, let pid = pid_t(fields[0]), let uid = uid_t(fields[1]),
                      uid == getuid(), pid != getpid(), let path = Self.executablePath(pid), Self.isClaudeCLIPath(path, command: String(fields[2])) else { continue }
                targets[pid] = path
            }
        } catch { fputs("无法查询 Claude Code 会话\n", stderr); return 1 }
        if targets.isEmpty { print("没有匹配的 Claude 会话"); return 0 }
        for pid in targets.keys.sorted() { print("PID \(pid)：\(targets[pid]!)") }
        if dryRun { print("仅预览，未终止任何进程。"); return 0 }
        _ = killDesktopIfRunning()
        var failed = false
        for (pid, path) in targets where !desktopIDs.contains(pid) {
            guard Self.executablePath(pid) == path else { continue }
            if kill(pid, SIGKILL) != 0 && errno != ESRCH { failed = true }
        }
        // Let the existing Desktop helper cleanup's delayed pass finish.
        if !desktopIDs.isEmpty { Thread.sleep(forTimeInterval: 0.2) }
        return failed ? 1 : 0
    }

    func showBlockedAlert(reason: String) {
        if headless {
            let alert = Process()
            alert.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
            alert.arguments = ["--blocked-alert", reason]
            try? alert.run()
            return
        }
        DispatchQueue.main.async {
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "ClaudeGuard 已拦截"
            alert.informativeText = "Claude 桌面端已关闭。\n\n\(reason)"
            alert.addButton(withTitle: "知道了")
            alert.window.level = .floating
            alert.runModal()
            if self.alertOnly { NSApp.terminate(nil) }
        }
    }

    @discardableResult
    func runHelper(_ cmd: String, _ a1: String, _ a2: String) -> Process? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        let script = NSString(string: "~/.local/share/ClaudeGuard/src/helper.py").expandingTildeInPath
        task.arguments = [script, cmd, a1, a2]
        do { try task.run(); return task } catch { return nil }
    }

    // MARK: - Config

    func loadConfig() {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            policyConfig = ["access_mode": "invalid"]
            protectionEnabled = true
            return
        }
        if let ips = json["allowed_ips"] as? [String] { allowedIPs = ips }
        policyConfig = json
        let storedMode = json["ip_check_mode"] == nil ? "both" : ((json["ip_check_mode"] as? String) ?? "invalid")
        ipCheckMode = storedMode == "auto" ? "both" : storedMode
        if let p = json["protection_enabled"] as? Bool { protectionEnabled = p }
        if let u = json["block_auto_updates"] as? Bool { blockAutoUpdates = u }
        if let m = json["model_override_enabled"] as? Bool { modelOverrideEnabled = m }
        if let d = json["default_model"] as? String { defaultModel = d }
    }

    func saveConfig() {
        var json: [String: Any] = [:]
        if let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
           let existing = try? JSONSerialization.jsonObject(with: data) as? [String: Any] { json = existing }
        for key in ["access_mode", "risk_threshold", "risk_cache_ttl", "detect_ip_change", "allow_unknown_ip", "check_interval", "http_proxy", "cli_http_proxy_enabled"] {
            if let value = policyConfig[key] { json[key] = value }
        }
        json["allowed_ips"] = allowedIPs
        json["ip_check_mode"] = ipCheckMode
        json["protection_enabled"] = protectionEnabled
        json["block_auto_updates"] = blockAutoUpdates
        json["model_override_enabled"] = modelOverrideEnabled
        json["default_model"] = defaultModel
        if let data = try? JSONSerialization.data(withJSONObject: json, options: .prettyPrinted) {
            try? data.write(to: URL(fileURLWithPath: configPath), options: .atomic)
        }
    }

    // MARK: - UI

    var ipCheckModeTitle: String {
        switch ipCheckMode {
        case "both": return "HTTP 和 STUN"
        case "http": return "仅 HTTP"
        case "stun": return "仅 STUN"
        default: return "配置有误"
        }
    }

    func statusText() -> String {
        switch state {
        case .offline:  return "⚪ 暂时无法确认出口 IP"
        case .disabled: return "🟡 防护已关闭"
        case .allowed:  return "🟢 出口已通过访问检查"
        case .blocked:  return "🔴 出口未通过访问检查，已拦截"
        }
    }

    func updateStatusDisplay(isDimmed: Bool = false) {
        guard let button = statusItem?.button else { return }
        let symbol: String
        switch state {
        case .offline:  symbol = "shield.slash.fill"   // crossed-out shield: nothing to verify against
        case .disabled: symbol = "shield"
        case .allowed:  symbol = "lock.shield.fill"
        case .blocked:  symbol = "xmark.shield.fill"
        }

        if displayedSymbol != symbol, let image = NSImage(systemSymbolName: symbol, accessibilityDescription: "ClaudeGuard")?
            .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 15, weight: .semibold)) {
            image.isTemplate = true
            button.image = image
            button.image?.accessibilityDescription = statusText()
            displayedSymbol = symbol
        }
        button.alphaValue = isDimmed ? 0.35 : 1.0
    }

    func startBlinking() {
        guard !headless else { return }
        DispatchQueue.main.async { [self] in
            guard blinkTimer == nil else { return }
            blinkState = false
            // Quick, smooth opacity pulse that fades in/out (like the system's
            // menu-bar input-source switcher) instead of a slow hard blink.
            blinkTimer = Timer.scheduledTimer(withTimeInterval: 0.16, repeats: true) { [weak self] _ in
                guard let self = self, let button = self.statusItem.button else { return }
                self.blinkState.toggle()
                NSAnimationContext.runAnimationGroup { ctx in
                    ctx.duration = 0.14
                    ctx.allowsImplicitAnimation = true
                    button.animator().alphaValue = self.blinkState ? 0.45 : 1.0
                }
            }
        }
    }

    func stopBlinking() {
        guard !headless else { return }
        DispatchQueue.main.async { [self] in
            let wasBlinking = blinkTimer != nil
            blinkTimer?.invalidate()
            blinkTimer = nil
            updateStatusDisplay()
            if wasBlinking, let button = statusItem.button {
                NSAnimationContext.runAnimationGroup { ctx in
                    ctx.duration = 0.14
                    ctx.allowsImplicitAnimation = true
                    button.animator().alphaValue = 1.0
                }
            }
        }
    }

    func menuNeedsUpdate(_ menu: NSMenu) { rebuildMenu() }

    func menuDidClose(_ menu: NSMenu) {
        guard settingsOnly, menu === self.menu else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.closeSettingsWhenIdle() }
    }

    func closeSettingsWhenIdle() {
        if settingsBusy || NSApp.modalWindow != nil {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.closeSettingsWhenIdle() }
        } else {
            NSApp.terminate(nil)
        }
    }

    func refreshSettingsState() {
        loadConfig()
        let path = URL(fileURLWithPath: configPath).deletingLastPathComponent().appendingPathComponent("state.json")
        if let data = try? Data(contentsOf: path),
           let snapshot = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let updated = snapshot["updated_at"] as? Double,
           Date().timeIntervalSince1970 - updated <= max(7, checkInterval + 4) {
            currentIP = snapshot["ip"] as? String ?? "No Internet"
            detectedIPs = snapshot["detected_ips"] as? [String: String] ?? [:]
            policyReason = snapshot["reason"] as? String ?? ""
            riskScores = snapshot["scores"] as? [String: Any] ?? [:]
            jumpBlocked = snapshot["jump_latched"] as? Bool == true
            switch snapshot["state"] as? String {
            case "allowed": state = .allowed(ip: currentIP)
            case "blocked": state = .blocked(ip: currentIP)
            case "disabled": state = .disabled
            default: state = .offline
            }
        } else {
            state = .offline
            currentIP = "No Internet"
            policyReason = "后台检测结果未更新，请运行 claudeguard start"
        }
        updateStatusDisplay()
    }

    func rebuildMenu() {
        menu.removeAllItems()

        let status = NSMenuItem(title: statusText(), action: nil, keyEquivalent: "")
        status.isEnabled = false
        menu.addItem(status)

        let ipItem = NSMenuItem(title: "🌐 当前出口：\(currentIP == "No Internet" ? "未获取" : currentIP)", action: nil, keyEquivalent: "")
        ipItem.isEnabled = false
        menu.addItem(ipItem)
        if !policyReason.isEmpty {
            let reason = NSMenuItem(title: policyReason, action: nil, keyEquivalent: "")
            reason.isEnabled = false
            menu.addItem(reason)
        }
        for ip in riskScores.keys.sorted() {
            if let entry = riskScores[ip] as? [String: Any], let score = entry["score"] as? NSNumber {
                let cached = entry["cached"] as? Bool == true ? "缓存" : "刚查询"
                let detail = NSMenuItem(title: "风险分：\(ip)  \(score)/100（\(cached)）", action: nil, keyEquivalent: "")
                detail.isEnabled = false
                menu.addItem(detail)
            }
        }

        menu.addItem(.separator())

        let recheck = NSMenuItem(title: "🔄 重新检测", action: #selector(onRecheck), keyEquivalent: "")
        recheck.target = self
        menu.addItem(recheck)

        let windows = NSMenuItem(title: "额度与窗口（Claude-W）", action: nil, keyEquivalent: "")
        let windowMenu = NSMenu()
        for (title, args) in [("状态与额度（本地缓存）", ["status", "--cached"]),
                              ("刷新实时额度", ["usage"]), ("请求历史", ["history"]),
                              ("调度预演（离线）", ["dry-run"]), ("启用周期自动请求…", ["auto"]),
                              ("停止定时请求", ["stop"]), ("取消计划", ["cancel"]),
                              ("立即尝试最小请求…", ["poke"]), ("预览终止范围", ["kill", "--dry-run"])] {
            let item = NSMenuItem(title: title, action: #selector(onWindowAction(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = args
            windowMenu.addItem(item)
        }
        let command = NSMenuItem(title: "创建计划 / 其他窗口命令…", action: #selector(onWindowCommand), keyEquivalent: "")
        command.target = self
        windowMenu.addItem(command)
        windows.submenu = windowMenu
        menu.addItem(windows)

        menu.addItem(.separator())

        let prot = NSMenuItem(title: protectionEnabled ? "✓ 防护已开启" : "防护已关闭", action: #selector(onToggleProtection), keyEquivalent: "")
        prot.target = self
        menu.addItem(prot)

        let modeItem = NSMenuItem(title: "出口检测：\(ipCheckModeTitle)", action: nil, keyEquivalent: "")
        let modeMenu = NSMenu()
        for (value, title) in [("both", "同时检查 HTTP 和 STUN（两项都须通过）"), ("http", "只检查 HTTP"), ("stun", "只检查 STUN")] {
            let item = NSMenuItem(title: title, action: #selector(onSelectIPCheckMode(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = value
            item.state = ipCheckMode == value ? .on : .off
            modeMenu.addItem(item)
        }
        modeItem.submenu = modeMenu
        menu.addItem(modeItem)

        let access = policyConfig["access_mode"] as? String ?? "whitelist"
        let jump = policyConfig["detect_ip_change"] as? Bool == true
        let jumpToggle = NSMenuItem(title: jump ? "✓ 检测 IP 跳变" : "检测 IP 跳变", action: #selector(onToggleIPChange), keyEquivalent: "")
        jumpToggle.target = self
        menu.addItem(jumpToggle)

        let allowUnknown = policyConfig["allow_unknown_ip"] as? Bool == true
        let allowToggle = NSMenuItem(title: allowUnknown ? "✓ 无法检测到 IP 时放行" : "无法检测到 IP 时放行", action: #selector(onToggleAllowUnknownIP), keyEquivalent: "")
        allowToggle.target = self
        menu.addItem(allowToggle)
        if jump && jumpBlocked {
            let ack = NSMenuItem(title: "信任当前 IP 并解除拦截…", action: #selector(onAcknowledgeIPChange), keyEquivalent: "")
            ack.target = self
            menu.addItem(ack)
        }

        let settingsItem = NSMenuItem(title: "设置", action: nil, keyEquivalent: "")
        let settingsMenu = NSMenu()
        let logs = NSMenuItem(title: "查看检测日志…", action: #selector(onOpenLogs), keyEquivalent: "")
        logs.target = self
        settingsMenu.addItem(logs)
        settingsMenu.addItem(.separator())
        let cliProxy = NSMenuItem(title: "Claude Code 始终使用 HTTP 代理", action: #selector(onToggleCLIProxy), keyEquivalent: "")
        cliProxy.target = self
        cliProxy.state = policyConfig["cli_http_proxy_enabled"] as? Bool == true ? .on : .off
        settingsMenu.addItem(cliProxy)
        let proxyAddress = NSMenuItem(title: "HTTP 代理地址…", action: #selector(onCLIProxyAddress), keyEquivalent: "")
        proxyAddress.target = self
        settingsMenu.addItem(proxyAddress)
        settingsMenu.addItem(.separator())
        let interval = NSMenuItem(title: "轮询间隔：\(checkInterval) 秒…", action: #selector(onCheckInterval), keyEquivalent: "")
        interval.target = self
        settingsMenu.addItem(interval)
        settingsMenu.addItem(.separator())
        if access == "risk" {
            let cache = NSMenuItem(title: "评分缓存时间…", action: #selector(onRiskCacheTTL), keyEquivalent: "")
            cache.target = self
            settingsMenu.addItem(cache)
            settingsMenu.addItem(.separator())
        }
        let upd = NSMenuItem(title: blockAutoUpdates ? "✓ 已禁止自动更新" : "允许自动更新", action: #selector(onToggleUpdates), keyEquivalent: "")
        upd.target = self
        settingsMenu.addItem(upd)

        settingsMenu.addItem(.separator())

        let modelToggle = NSMenuItem(title: modelOverrideEnabled ? "✓ 固定模型：\(defaultModel)" : "固定模型（未启用）", action: #selector(onToggleModelOverride), keyEquivalent: "")
        modelToggle.target = self
        settingsMenu.addItem(modelToggle)

        if modelOverrideEnabled {
            let changeModel = NSMenuItem(title: "    更换模型…", action: #selector(onChangeModel), keyEquivalent: "")
            changeModel.target = self
            settingsMenu.addItem(changeModel)
        }

        settingsItem.submenu = settingsMenu
        menu.addItem(settingsItem)
        menu.addItem(.separator())

        let rules = NSMenuItem(title: "访问规则：" + (access == "risk" ? "风险评分" : "IP 白名单"), action: nil, keyEquivalent: "")
        let rulesMenu = NSMenu()
        for (value, title) in [("whitelist", "固定 IP 白名单"), ("risk", "按风险分阈值判断")] {
            let item = NSMenuItem(title: title, action: #selector(onSelectAccessMode(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = value
            item.state = access == value ? .on : .off
            rulesMenu.addItem(item)
        }
        rules.submenu = rulesMenu
        menu.addItem(rules)
        if access == "risk" {
            let thresholdValue = policyConfig["risk_threshold"] as? NSNumber ?? 50
            let threshold = NSMenuItem(title: "风险分阈值：\(thresholdValue)…", action: #selector(onRiskThreshold), keyEquivalent: "")
            threshold.target = self
            menu.addItem(threshold)
        } else if access == "whitelist" {
            for ip in Set(detectedIPs.values).sorted() where !allowedIPs.contains(ip) {
                let add = NSMenuItem(title: "➕ 将 \(ip) 加入白名单", action: #selector(onAddCurrentIP(_:)), keyEquivalent: "")
                add.target = self
                add.representedObject = ip
                menu.addItem(add)
            }

            let manage = NSMenuItem(title: "⚙️ 管理 IP 白名单…", action: #selector(onManageIPs), keyEquivalent: "")
            manage.target = self
            menu.addItem(manage)

        }

        menu.addItem(.separator())

        let quit = NSMenuItem(title: settingsOnly ? "关闭设置（防护继续运行）" : "退出 ClaudeGuard", action: #selector(onQuit), keyEquivalent: "")
        quit.target = self
        menu.addItem(quit)
    }

    private func recheckAsync() {
        if settingsOnly {
            DistributedNotificationCenter.default().postNotificationName(Self.recheckNotification, object: nil, userInfo: nil, deliverImmediately: true)
            return
        }
        startBlinking()
        DispatchQueue.global(qos: .userInitiated).async { self.recheck() }
    }

    @objc func onWindowAction(_ sender: NSMenuItem) {
        guard let args = sender.representedObject as? [String] else { return }
        runWindowCommand(args)
    }

    @objc func onWindowCommand() {
        let alert = NSAlert()
        alert.messageText = "Claude-W 窗口管理"
        alert.informativeText = "例如：10:00 -n 3（三次）、10:00 -d（每天）、schedule tomorrow 10:00、config --expected-ip <IPv4>、kill --dry-run、kill。创建计划会启用任务并消耗订阅额度。"
        let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 360, height: 24))
        input.placeholderString = "10:00 -n 3"
        alert.accessoryView = input
        alert.addButton(withTitle: "下一步")
        alert.addButton(withTitle: "取消")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        runWindowCommand(input.stringValue.split(whereSeparator: { $0.isWhitespace }).map(String.init))
    }

    func runWindowCommand(_ args: [String]) {
        guard !args.isEmpty, !settingsBusy else { return }
        let preview = args.contains("--dry-run")
        let action = args[0]
        if !preview && (["auto", "start", "poke", "schedule", "kill", "ckill"].contains(action) || action.contains(":")) {
            let confirm = NSAlert()
            confirm.messageText = "执行窗口管理命令？"
            confirm.informativeText = args.joined(separator: " ") + "\n\n" +
                (["kill", "ckill"].contains(action) ? "将终止当前用户的 Claude 会话，未保存内容可能丢失。ClaudeGuard 保持运行。" : "创建计划、启用自动模式或立即尝试会发送最小模型请求并消耗订阅额度。仍须通过出口、防护、登录及额度检查。")
            confirm.addButton(withTitle: "执行")
            confirm.addButton(withTitle: "取消")
            guard confirm.runModal() == .alertFirstButtonReturn else { return }
        }
        settingsBusy = true
        DispatchQueue.global(qos: .utility).async {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
            process.arguments = [NSString(string: "~/.local/share/ClaudeGuard/bin/claude-w").expandingTildeInPath] + args
            let output = Pipe()
            process.standardOutput = output
            process.standardError = output
            let text: String
            do {
                try process.run()
                let data = output.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                text = String(data: data, encoding: .utf8) ?? "无法读取结果"
            } catch { text = "窗口管理启动失败：\(error.localizedDescription)" }
            DispatchQueue.main.async {
                let notice = NSAlert()
                notice.messageText = "Claude-W 执行结果"
                notice.informativeText = text.isEmpty ? "命令已结束，无输出。" : text
                notice.addButton(withTitle: "关闭")
                notice.runModal()
                self.settingsBusy = false
            }
        }
    }

    func runPolicy(action: String, request: [String: Any]) -> [String: Any] {
        let failure: [String: Any] = ["state": "blocked", "reason": "策略检查失败，暂不放行"]
        guard let encoded = try? JSONSerialization.data(withJSONObject: request) else { return failure }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = [policyScriptPath, "--config", configPath, action]
        let input = Pipe(), output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let done = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }
        do { try process.run() } catch { return failure }
        input.fileHandleForWriting.write(encoded)
        input.fileHandleForWriting.closeFile()
        if done.wait(timeout: .now() + 45) == .timedOut {
            process.terminate()
            return failure
        }
        let raw = output.fileHandleForReading.readDataToEndOfFile()
        return (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any] ?? failure
    }

    func evaluatePolicy(data: [String: Any], ips: [String: String]) -> [String: Any] {
        let request: [String: Any] = ["data": data, "ips": ips]
        let encoded = try? JSONSerialization.data(withJSONObject: request, options: .sortedKeys)
        let path = URL(fileURLWithPath: configPath).deletingLastPathComponent().appendingPathComponent("admission-state.json")
        let before = try? Data(contentsOf: path)
        if encoded == cachedPolicyRequest, before == cachedPolicyState, Date() >= cachedPolicyCreated, Date() < cachedPolicyExpires,
           var outcome = cachedPolicyOutcome {
            if var scores = outcome["scores"] as? [String: [String: Any]] {
                for ip in Array(scores.keys) { scores[ip]?["cached"] = true }
                outcome["scores"] = scores
            }
            return outcome
        }
        cachedPolicyOutcome = nil
        let outcome = runPolicy(action: "evaluate", request: request)
        // Reuse stable policy transactions; fresh IP probes and shared-state reads still run every tick.
        let resultState = outcome["state"] as? String
        let scores = outcome["scores"] as? [String: [String: Any]] ?? [:]
        let reusable = resultState == "allowed" || (resultState == "blocked"
            && outcome["reason"] as? String != "策略检查失败，暂不放行"
            && (data["access_mode"] as? String ?? "whitelist" != "risk" || outcome["jump_latched"] as? Bool == true || !scores.isEmpty))
        if encoded != nil, reusable, before == (try? Data(contentsOf: path)) {
            var expires = Date.distantFuture
            let ttl = (data["risk_cache_ttl"] as? NSNumber)?.doubleValue ?? 21600
            for entry in scores.values {
                expires = min(expires, Date(timeIntervalSince1970: ((entry["fetched_at"] as? NSNumber)?.doubleValue ?? 0) + ttl))
            }
            cachedPolicyRequest = encoded
            cachedPolicyState = before
            cachedPolicyOutcome = outcome
            cachedPolicyCreated = Date()
            cachedPolicyExpires = expires
        }
        return outcome
    }

    @objc func onSelectAccessMode(_ sender: NSMenuItem) {
        guard let mode = sender.representedObject as? String else { return }
        if mode == "risk" {
            let alert = NSAlert()
            alert.messageText = "使用风险评分判断出口？"
            alert.informativeText = "将向 proxycheck.io 查询出口 IP 的风险分，并缓存结果。超过你设置的阈值或无法取得有效评分时，都会拦截。"
            alert.addButton(withTitle: "使用风险评分")
            alert.addButton(withTitle: "取消")
            guard alert.runModal() == .alertFirstButtonReturn else { return }
        }
        policyConfig["access_mode"] = mode
        saveConfig()
        recheckAsync()
    }

    func setPolicyNumber(key: String, title: String, fallback: Double, min: Double, max: Double) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = "可填范围：\(min)～\(max)。"
        let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        input.stringValue = String((policyConfig[key] as? NSNumber)?.doubleValue ?? fallback)
        alert.accessoryView = input
        alert.addButton(withTitle: "保存")
        alert.addButton(withTitle: "取消")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard let number = Double(input.stringValue), number.isFinite, number >= min, number <= max else {
            let error = NSAlert()
            error.messageText = "输入无效，请填写范围内的数字。"
            error.runModal()
            return
        }
        policyConfig[key] = number
        saveConfig()
        recheckAsync()
    }
    @discardableResult func editCLIProxyAddress() -> Bool {
        let alert = NSAlert()
        alert.messageText = "HTTP 代理地址"
        alert.informativeText = "例如 http://127.0.0.1:7897。用于 HTTP 出口检测及勾选后新启动的 Claude Code，不修改终端的全局代理。"
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 340, height: 24))
        field.stringValue = policyConfig["http_proxy"] as? String ?? ""
        alert.accessoryView = field
        alert.addButton(withTitle: "保存")
        alert.addButton(withTitle: "取消")
        guard alert.runModal() == .alertFirstButtonReturn else { return false }
        let value = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URLComponents(string: value), url.scheme == "http",
              let host = url.host, !host.isEmpty, let port = url.port, (1...65535).contains(port),
              url.user == nil, url.password == nil, ["", "/"].contains(url.path), url.query == nil, url.fragment == nil,
              value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else {
            let error = NSAlert()
            error.messageText = "代理地址无效"
            error.informativeText = "请填写包含协议和端口的地址，不含账号密码，例如 http://127.0.0.1:7897。"
            error.runModal()
            return false
        }
        policyConfig["http_proxy"] = value
        saveConfig()
        recheckAsync()
        return true
    }
    @objc func onCLIProxyAddress() { editCLIProxyAddress() }
    @objc func onToggleCLIProxy() {
        let enabled = policyConfig["cli_http_proxy_enabled"] as? Bool == true
        if !enabled && (policyConfig["http_proxy"] as? String ?? "").isEmpty {
            guard editCLIProxyAddress() else { return }
        }
        policyConfig["cli_http_proxy_enabled"] = !enabled
        saveConfig()
        rebuildMenu()
    }
    @objc func onOpenLogs() {
        logEvent("log_opened")
        NSWorkspace.shared.open(URL(fileURLWithPath: eventLogPath))
    }
    @objc func onCheckInterval() {
        setPolicyNumber(key: "check_interval", title: "出口轮询间隔（秒，建议 3 秒）", fallback: 3, min: 1, max: 60)
        configurePolling()
    }
    @objc func onRiskThreshold() {
        setPolicyNumber(key: "risk_threshold", title: "超过多少风险分时拦截？", fallback: 50, min: 0, max: 100)
    }
    @objc func onRiskCacheTTL() {
        setPolicyNumber(key: "risk_cache_ttl", title: "评分缓存时间（秒）", fallback: 21600, min: 1, max: 604800)
    }
    @objc func onToggleIPChange() {
        policyConfig["detect_ip_change"] = !(policyConfig["detect_ip_change"] as? Bool ?? false)
        saveConfig()
        recheckAsync()
    }
    @objc func onToggleAllowUnknownIP() {
        policyConfig["allow_unknown_ip"] = !(policyConfig["allow_unknown_ip"] as? Bool ?? false)
        saveConfig()
        recheckAsync()
    }
    @objc func onAcknowledgeIPChange() {
        let expected = detectedIPs
        let data = policyConfig
        let mode = ipCheckMode
        let alert = NSAlert()
        alert.messageText = "信任当前 IP 并解除跳变拦截？"
        alert.informativeText = "当前出口：\(currentIP)\n\n如果这是你主动切换的线路，可以确认信任。程序会重新检测 IP，确认地址未变后，解除跳变拦截，并将当前 IP 设为新的检测基准。白名单和风险评分仍会单独检查，不通过时继续拦截。"
        alert.addButton(withTitle: "信任并重新检查")
        alert.addButton(withTitle: "取消")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        settingsBusy = true
        DispatchQueue.global(qos: .userInitiated).async {
            let freshIPs = self.detectExits(mode: mode)
            let result = self.runPolicy(action: "ack-evaluate", request: ["data": data, "ips": freshIPs, "expected_ips": expected])
            self.recheckAsync()
            DispatchQueue.main.async {
                let notice = NSAlert()
                let acknowledged = result["jump_acknowledged"] as? Bool == true
                notice.messageText = acknowledged ? (result["state"] as? String == "allowed" ? "已解除跳变拦截，允许使用" : "已解除跳变拦截，访问检查未通过") : "未解除跳变拦截"
                notice.informativeText = result["reason"] as? String ?? "策略检查失败"
                notice.addButton(withTitle: "知道了")
                notice.runModal()
                self.settingsBusy = false
            }
        }
    }

    @objc func onRecheck() { recheckAsync() }

    @objc func onSelectIPCheckMode(_ sender: NSMenuItem) {
        guard let mode = sender.representedObject as? String,
              ["both", "http", "stun"].contains(mode) else { return }
        ipCheckMode = mode
        saveConfig()
        rebuildMenu()
        recheckAsync()
    }

    @objc func onToggleProtection() {
        protectionEnabled.toggle()
        saveConfig()
        rebuildMenu()        // reflect the toggle instantly; enforcement follows
        recheckAsync()
    }

    @objc func onToggleUpdates() {
        blockAutoUpdates.toggle()
        saveConfig()
        rebuildMenu()        // reflect the toggle instantly; enforcement follows
        recheckAsync()
    }

    @objc func onToggleModelOverride() {
        modelOverrideEnabled.toggle()
        saveConfig()
        rebuildMenu()
    }

    @objc func onChangeModel() {
        let script = "display dialog \"输入模型名称，例如 claude-opus-4-8：\" default answer \"\(defaultModel)\" with title \"ClaudeGuard 固定模型\" buttons {\"取消\", \"保存\"} default button \"保存\" cancel button \"取消\""
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        let pipe = Pipe()
        process.standardOutput = pipe
        try? process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        if let out = String(data: data, encoding: .utf8), out.contains("text returned:") {
            let parts = out.components(separatedBy: "text returned:")
            if parts.count > 1 {
                let raw = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
                if !raw.isEmpty {
                    defaultModel = raw
                    saveConfig()
                    rebuildMenu()
                }
            }
        }
    }

    @objc func onAddCurrentIP(_ sender: NSMenuItem) {
        guard let ip = sender.representedObject as? String, !allowedIPs.contains(ip) else { return }
        allowedIPs.append(ip)
        saveConfig()
        recheckAsync()
    }

    @objc func onManageIPs() {
        let ipsStr = allowedIPs.joined(separator: ", ")
        let script = "display dialog \"输入允许使用的出口 IP 或 CIDR 网段，多个地址用英文逗号分隔：\" default answer \"\(ipsStr)\" with title \"ClaudeGuard IP 白名单\" buttons {\"取消\", \"保存\"} default button \"保存\" cancel button \"取消\""
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        let pipe = Pipe()
        process.standardOutput = pipe
        try? process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        if let out = String(data: data, encoding: .utf8), out.contains("text returned:") {
            let parts = out.components(separatedBy: "text returned:")
            if parts.count > 1 {
                let raw = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
                allowedIPs = raw.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                saveConfig()
                recheckAsync()
            }
        }
    }

    @objc func onQuit() { NSApplication.shared.terminate(nil) }
}

// MARK: - Entry point
if CommandLine.arguments.contains("--kill-sessions") {
    exit(AppDelegate().closeClaudeSessions(dryRun: CommandLine.arguments.contains("--dry-run")))
} else if CommandLine.arguments.contains("--daemon") {
    let delegate = AppDelegate()
    delegate.headless = true
    guard delegate.acquireDaemonLock() else { exit(0) }
    delegate.startGuard()
    RunLoop.main.run()
} else {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let delegate = AppDelegate()
    delegate.settingsOnly = true
    delegate.alertOnly = CommandLine.arguments.contains("--blocked-alert")
    app.delegate = delegate
    app.run()
}
