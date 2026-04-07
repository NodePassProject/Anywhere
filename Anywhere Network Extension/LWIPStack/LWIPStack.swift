//
//  LWIPStack.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation
import NetworkExtension

private let logger = TunnelLogger(category: "LWIPStack")

// MARK: - LWIPStack

/// Main coordinator for the lwIP TCP/IP stack.
///
/// All lwIP calls run on a single serial `DispatchQueue` (`lwipQueue`).
/// One instance per Network Extension process, accessible via ``shared``.
///
/// Reads IP packets from the tunnel's `NEPacketTunnelFlow`, feeds them into
/// lwIP for TCP/UDP reassembly, and dispatches resulting connections through
/// VLESS proxy clients. Response data is written back to the packet flow.
class LWIPStack {

    // MARK: Properties

    /// Serial queue for all lwIP operations (lwIP is not thread-safe).
    let lwipQueue = DispatchQueue(label: "com.argsment.Anywhere.lwip")

    /// Queue for writing packets back to the tunnel.
    let outputQueue = DispatchQueue(label: "com.argsment.Anywhere.output")

    var packetFlow: NEPacketTunnelFlow?
    var configuration: ProxyConfiguration?

    static let ipv4Proto = NSNumber(value: AF_INET)
    static let ipv6Proto = NSNumber(value: AF_INET6)
    var outputPackets: [Data] = []
    var outputProtocols: [NSNumber] = []
    var outputFlushScheduled = false
    /// True while a writePackets call is executing on outputQueue.
    /// Prevents piling up multiple writes that overwhelm the TUN device buffer.
    var outputWriteInFlight = false

    // --- Settings (read from App Group UserDefaults) ---
    // These are loaded at start/restart and live-reloaded via Darwin notification.
    //
    // Setting                 │ Where it takes effect               │ On change
    // ────────────────────────┼─────────────────────────────────────┼──────────────────────────────
    // ipv6DNSEnabled          │ lwIP DNS interception (AAAA fake IP)│ Stack restart
    // encryptedDNSEnabled     │ lwIP DNS interception (DDR block),  │ Reapply tunnel settings +
    //                         │ tunnel DNS settings (DoH/DoT)       │ stack restart
    // bypassCountryEnabled     │ DomainRouter bypass rules gate      │ Stack restart
    // routingRules            │ DomainRouter (connection-time)      │ Stack restart (closes connections
    //                         │                                     │ using outdated proxy configurations;
    //                         │                                     │ FakeIPPool preserved)

    var ipv6DNSEnabled: Bool = false
    var encryptedDNSEnabled: Bool = false
    var encryptedDNSProtocol: String = "doh"
    var encryptedDNSServer: String = ""
    var proxyMode: ProxyMode = .rule
    var running = false

    // lwIP periodic timeout timer
    var timeoutTimer: DispatchSourceTimer?

    /// Active bypass country code (empty = disabled).
    /// Used to gate DomainRouter bypass flags and detect settings changes.
    var bypassCountryCode: String = ""

    /// All proxy server addresses (domains and resolved IPs) from all configurations.
    /// Updated via IPC from the app when configurations change. The extension also
    /// resolves domains to IPs so it can match connections by IP address.
    private var proxyServerAddresses: Set<String> = []

    /// Global traffic counters (bytes through the tunnel).
    /// Incremented on lwipQueue; read from the NE provider message handler thread.
    /// Small races are tolerable — these are only used for UI display.
    var totalBytesIn: Int64 = 0
    var totalBytesOut: Int64 = 0

    // MARK: - Log Buffer
    //
    // Stores recent log messages for display in the main app's log viewer.
    // Entries older than 5 minutes or exceeding 50 items are pruned on
    // each append or fetch.
    // Thread-safe via NSLock — logs may be appended from NWConnection
    // completion handlers (not on lwipQueue), while fetches come from IPC.

    enum LogLevel: String {
        case info
        case warning
        case error
    }

    struct LogEntry {
        let timestamp: CFAbsoluteTime
        let level: LogLevel
        let message: String
    }

    struct RecentTunnelInterruption {
        let timestamp: CFAbsoluteTime
        let level: LogLevel
        let summary: String
    }

    private let logLock = NSLock()
    private var logEntries: [LogEntry] = []
    private let recentTunnelInterruptionLock = NSLock()
    private var recentTunnelInterruption: RecentTunnelInterruption?

    /// Appends a log message to the buffer. Thread-safe.
    func appendLog(_ message: String, level: LogLevel) {
        let now = CFAbsoluteTimeGetCurrent()
        logLock.lock()
        logEntries.append(LogEntry(timestamp: now, level: level, message: message))
        compactLogs(now: now)
        logLock.unlock()
    }

    /// Returns all log entries within the retention window as serializable dictionaries.
    func fetchLogs() -> [[String: Any]] {
        let now = CFAbsoluteTimeGetCurrent()
        logLock.lock()
        compactLogs(now: now)
        let result = logEntries.map { entry in
            ["timestamp": entry.timestamp, "level": entry.level.rawValue, "message": entry.message] as [String: Any]
        }
        logLock.unlock()
        return result
    }

    /// Removes entries older than the retention window, then trims the oldest
    /// entries if the buffer still exceeds `logMaxEntries`. Caller must hold `logLock`.
    private func compactLogs(now: CFAbsoluteTime) {
        let cutoff = now - TunnelConstants.logRetentionInterval
        logEntries.removeAll { $0.timestamp < cutoff }
        if logEntries.count > TunnelConstants.logMaxEntries {
            logEntries.removeFirst(logEntries.count - TunnelConstants.logMaxEntries)
        }
    }

    /// Records a recent tunnel-level interruption so connection errors that follow
    /// can be reclassified as VPN/path interruptions instead of generic failures.
    func noteRecentTunnelInterruption(summary: String, level: LogLevel) {
        recentTunnelInterruptionLock.lock()
        recentTunnelInterruption = RecentTunnelInterruption(
            timestamp: CFAbsoluteTimeGetCurrent(),
            level: level,
            summary: summary
        )
        recentTunnelInterruptionLock.unlock()
    }

    /// Returns the most recent tunnel interruption if it is still fresh enough
    /// to explain follow-up socket failures.
    func recentTunnelInterruptionContext() -> RecentTunnelInterruption? {
        let now = CFAbsoluteTimeGetCurrent()
        recentTunnelInterruptionLock.lock()
        defer { recentTunnelInterruptionLock.unlock() }

        guard let recentTunnelInterruption else { return nil }
        guard now - recentTunnelInterruption.timestamp <= TunnelConstants.recentTunnelInterruptionWindow else {
            self.recentTunnelInterruption = nil
            return nil
        }
        return recentTunnelInterruption
    }

    /// Mux manager for multiplexing UDP flows (created when Vision flow is active).
    var muxManager: MuxManager?

    /// Hashable key for UDP flows — avoids per-packet string interpolation.
    struct UDPFlowKey: Hashable, CustomStringConvertible {
        let srcHost: String
        let srcPort: UInt16
        let dstHost: String
        let dstPort: UInt16

        var description: String {
            "\(srcHost):\(srcPort)-\(dstHost):\(dstPort)"
        }
    }

    /// Active UDP flows keyed by 5-tuple.
    var udpFlows: [UDPFlowKey: LWIPUDPFlow] = [:]
    var udpCleanupTimer: DispatchSourceTimer?

    /// Domain-based DNS routing (loaded from App Group routing.json).
    let domainRouter = DomainRouter()

    /// Fake-IP pool for mapping domains to synthetic IPs.
    let fakeIPPool = FakeIPPool()

    /// Called when tunnel network settings need to be re-applied via `setTunnelNetworkSettings`.
    /// This resets the virtual interface and flushes the OS DNS cache, forcing apps to re-resolve.
    /// Triggered by: IPv6 toggle (route/DNS changes), routing rule changes (DNS cache flush).
    var onTunnelSettingsNeedReapply: (() -> Void)?

    /// Singleton for C callback access (one NE process = one stack).
    static var shared: LWIPStack?

    // MARK: - Proxy Server Address Bypass

    /// Returns true if traffic to the given host should bypass the tunnel.
    /// Checks proxy server addresses (prevents routing loops after config switch).
    /// Country-based bypass is handled entirely by DomainRouter rules.
    func shouldBypass(host: String) -> Bool {
        isProxyServerAddress(host)
    }

    /// Returns true if the given host matches any proxy server address across all
    /// configurations. Prevents routing loops and ensures latency tests bypass the tunnel.
    ///
    /// Checks the proxy server address set (domains + resolved IPs synced from the app)
    /// with a fallback to the active configuration in case IPC hasn't arrived yet.
    private func isProxyServerAddress(_ host: String) -> Bool {
        // Fast path: direct set lookup (covers domains and resolved IPs)
        if proxyServerAddresses.contains(host) { return true }
        // Fallback: check active config in case proxyServerAddresses hasn't been populated yet
        guard let configuration = configuration else { return false }
        if host == configuration.serverAddress || host == configuration.resolvedIP { return true }
        if let chain = configuration.chain {
            for proxy in chain {
                if host == proxy.serverAddress || host == proxy.resolvedIP { return true }
            }
        }
        return false
    }

    func clearRecentTunnelInterruption() {
        recentTunnelInterruptionLock.lock()
        recentTunnelInterruption = nil
        recentTunnelInterruptionLock.unlock()
    }

    // MARK: - Runtime Configuration

    func configureRuntime(for configuration: ProxyConfiguration, shouldLoadProxyServerAddresses: Bool) {
        loadIPv6Settings()
        loadBypassCountry()
        loadEncryptedDNSSetting()
        loadProxyModeSetting()
        if shouldLoadProxyServerAddresses {
            loadProxyServerAddresses()
        }

        if Self.shouldUseVisionMux(configuration) {
            muxManager = MuxManager(configuration: configuration, lwipQueue: lwipQueue)
        } else {
            muxManager = nil
        }

        if proxyMode != .global {
            domainRouter.loadRoutingConfiguration()
        }
    }

    private static func shouldUseVisionMux(_ configuration: ProxyConfiguration) -> Bool {
        configuration.outboundProtocol == .vless &&
        configuration.muxEnabled &&
        (configuration.flow == "xtls-rprx-vision" || configuration.flow == "xtls-rprx-vision-udp443")
    }

    /// Reads IPv6 settings from app group UserDefaults.
    private func loadIPv6Settings() {
        ipv6DNSEnabled = AWCore.userDefaults.bool(forKey: TunnelConstants.UserDefaultsKey.ipv6DNSEnabled)
    }

    /// Reads the bypass country code from app group UserDefaults.
    private func loadBypassCountry() {
        bypassCountryCode = AWCore.userDefaults.string(forKey: TunnelConstants.UserDefaultsKey.bypassCountryCode) ?? ""
    }

    // MARK: - Proxy Server Address Bypass

    /// Loads proxy server addresses from App Group UserDefaults and resolves
    /// domains to IPs in the background. Called on initial start.
    private func loadProxyServerAddresses() {
        guard let data = AWCore.userDefaults.data(forKey: TunnelConstants.UserDefaultsKey.proxyServerAddresses),
              let addresses = try? JSONSerialization.jsonObject(with: data) as? [String] else {
            return
        }
        // Use stale IPs temporarily
        proxyServerAddresses = Set(addresses)
        // Resolve domains to IPs in background
        Self.resolveProxyDomains(addresses) { [weak self] resolvedIPs in
            self?.lwipQueue.async {
                self?.proxyServerAddresses.formUnion(resolvedIPs)
            }
        }
    }

    /// Updates the set of proxy server addresses from the app via IPC.
    /// Immediately stores domains, then resolves them to IPs in the background.
    func updateProxyServerAddresses(_ addresses: [String]) {
        lwipQueue.async { [self] in
            // Use stale IPs temporarily
            proxyServerAddresses = Set(addresses)
            // Resolve domains to IPs in background
            Self.resolveProxyDomains(addresses) { [weak self] resolvedIPs in
                self?.lwipQueue.async {
                    guard let self else { return }
                    self.proxyServerAddresses.formUnion(resolvedIPs)
                }
            }
        }
    }

    /// Resolves an array of addresses (domains and IPs) to IP strings on a background queue.
    /// IPs pass through unchanged; domains are resolved via `getaddrinfo`.
    private static func resolveProxyDomains(_ addresses: [String], completion: @escaping (Set<String>) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            var resolvedIPs = Set<String>()
            for address in addresses {
                let ips = resolveHostname(address)
                resolvedIPs.formUnion(ips)
            }
            completion(resolvedIPs)
        }
    }

    /// Resolves a hostname to IP strings via getaddrinfo. Blocking — call from a background queue.
    private static func resolveHostname(_ hostname: String) -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(hostname, nil, &hints, &result) == 0, let res = result else { return [] }
        defer { freeaddrinfo(res) }

        var ips: [String] = []
        var current: UnsafeMutablePointer<addrinfo>? = res
        while let info = current {
            switch info.pointee.ai_family {
            case AF_INET:
                info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { ptr in
                    var sinAddr = ptr.pointee.sin_addr
                    var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    inet_ntop(AF_INET, &sinAddr, &buf, socklen_t(INET_ADDRSTRLEN))
                    ips.append(String(cString: buf))
                }
            case AF_INET6:
                info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { ptr in
                    var sin6Addr = ptr.pointee.sin6_addr
                    var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    inet_ntop(AF_INET6, &sin6Addr, &buf, socklen_t(INET6_ADDRSTRLEN))
                    ips.append(String(cString: buf))
                }
            default:
                break
            }
            current = info.pointee.ai_next
        }
        return ips
    }

    /// Reads encrypted DNS settings from app group UserDefaults.
    private func loadEncryptedDNSSetting() {
        encryptedDNSEnabled = AWCore.userDefaults.bool(forKey: TunnelConstants.UserDefaultsKey.encryptedDNSEnabled)
        encryptedDNSProtocol = AWCore.userDefaults.string(forKey: TunnelConstants.UserDefaultsKey.encryptedDNSProtocol) ?? TunnelConstants.defaultEncryptedDNSProtocol
        encryptedDNSServer = AWCore.userDefaults.string(forKey: TunnelConstants.UserDefaultsKey.encryptedDNSServer) ?? ""
    }

    private func loadProxyModeSetting() {
        proxyMode = AWCore.userDefaults.string(forKey: TunnelConstants.UserDefaultsKey.proxyMode).flatMap(ProxyMode.init) ?? .rule
    }

    // MARK: - IP Address Helpers

    /// Converts a raw IP address pointer to a human-readable string.
    ///
    /// - Parameters:
    ///   - addr: Pointer to the raw IP address bytes (4 bytes for IPv4, 16 bytes for IPv6).
    ///   - isIPv6: Whether the address is IPv6.
    /// - Returns: A string representation (e.g. "192.168.1.1" or "2001:db8::1").
    static func ipAddrToString(_ addr: UnsafeRawPointer, isIPv6: Bool) -> String {
        var buf = (
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0)
        ) // 46 bytes = INET6_ADDRSTRLEN
        return withUnsafeMutablePointer(to: &buf) { ptr in
            let cStr = ptr.withMemoryRebound(to: CChar.self, capacity: 46) { charPtr in
                lwip_ip_to_string(addr, isIPv6 ? 1 : 0, charPtr, 46)
            }
            if let cStr {
                return String(cString: cStr)
            }
            return "?"
        }
    }
}
