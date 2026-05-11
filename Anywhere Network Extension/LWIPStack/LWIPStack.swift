//
//  LWIPStack.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation
import NetworkExtension

private let logger = AnywhereLogger(category: "LWIPStack")

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
    let lwipQueue = DispatchQueue(label: AWCore.Identifier.lwipQueue)

    /// Queue for writing packets back to the tunnel.
    let outputQueue = DispatchQueue(label: AWCore.Identifier.outputQueue)

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

    /// Coalescing signal that runs the post-`writePackets` re-flush check on
    /// `lwipQueue`. Replaces a per-write `lwipQueue.async` back-hop with a
    /// `DispatchSource` whose handler invocation count is naturally bounded
    /// by `lwipQueue` availability — under sustained upload (an ACK
    /// `writePackets` per send completion × N connections), several signals
    /// land while `lwipQueue` is busy on input/completion/timer work and
    /// collapse into one handler call. Created in ``start`` /
    /// ``restartStackNow`` and cancelled in ``shutdownInternal``.
    var outputDrainSource: DispatchSourceUserDataAdd?

    // --- Settings (read from App Group UserDefaults) ---
    // These are loaded at start/restart and live-reloaded via Darwin notification.
    //
    // Setting                 │ Where it takes effect               │ On change
    // ────────────────────────┼─────────────────────────────────────┼──────────────────────────────
    // bypassCountryEnabled    │ DomainRouter bypass rules gate      │ Stack restart
    // ipv6DNSEnabled          │ lwIP DNS interception (AAAA fake IP)│ Stack restart
    // encryptedDNSEnabled     │ lwIP DNS interception (DDR block),  │ Reapply tunnel settings +
    //                         │ tunnel DNS settings (DoH/DoT)       │ stack restart
    // routingRules            │ DomainRouter (connection-time)      │ Stack restart (closes connections
    //                         │                                     │ using outdated proxy configurations;
    //                         │                                     │ FakeIPPool preserved)
    var proxyMode: ProxyMode = .rule
    var hideVPNIcon: Bool = false
    var blockQUICEnabled: Bool = true
    var ipv6DNSEnabled: Bool = false
    var encryptedDNSEnabled: Bool = false
    var encryptedDNSProtocol: String = "doh"
    var encryptedDNSServer: String = ""

    // MARK: MITM
    //
    // MITM state lives beside routing state: routing selects the upstream
    // proxy, while MITM decides whether to intercept TLS in transit.
    // With the master toggle off or no compiled rules, the connection path
    // stays unchanged.
    var mitmEnabled: Bool = false
    let mitmPolicy = MITMRewritePolicy()
    /// Lazily-created leaf certificate cache. Defers keychain access until a
    /// MITM session needs a leaf certificate.
    var mitmLeafCache: MITMLeafCertCache?
    let mitmCertificateStore = MITMCertificateStore()
    
    var running = false

    /// True while a deliberate TCP teardown is in progress (stack shutdown,
    /// restart, or wake handling). Set around ``lwip_bridge_abort_all_tcp``
    /// calls so ``LWIPTCPConnection.handleError`` can demote the resulting
    /// ERR_ABRT flood to debug — while still surfacing lwIP's own internal
    /// aborts (e.g., `tcp_kill_prio` under PCB pool exhaustion) as warnings.
    var isTearingDown = false

    /// Timestamp of the last completed stack restart (used for throttling).
    var lastRestartTime: CFAbsoluteTime = 0

    /// Pending deferred restart when throttled. Cancelled and replaced on each new request.
    var deferredRestart: DispatchWorkItem?

    /// lwIP periodic timeout timer
    var timeoutTimer: DispatchSourceTimer?

    /// Active bypass country code (empty = disabled).
    /// Used to gate DomainRouter bypass flags and detect settings changes.
    var bypassCountryCode: String = ""

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
    // Thread-safe via NSLock — logs may be appended from I/O completion
    // handlers off lwipQueue, while fetches come from IPC.

    typealias LogLevel = TunnelLogLevel
    typealias LogEntry = TunnelLogEntry

    struct RecentTunnelInterruption {
        let timestamp: CFAbsoluteTime
        let level: LogLevel
        let summary: String
    }

    private let logLock = NSLock()
    private var logEntries: [LogEntry] = []

    /// Appends a log message to the buffer. Thread-safe.
    func appendLog(_ message: String, level: LogLevel) {
        let now = CFAbsoluteTimeGetCurrent()
        logLock.lock()
        logEntries.append(LogEntry(timestamp: now, level: level, message: message))
        compactLogs(now: now)
        logLock.unlock()
    }

    /// Returns all log entries within the retention window.
    func fetchLogs() -> [LogEntry] {
        let now = CFAbsoluteTimeGetCurrent()
        logLock.lock()
        compactLogs(now: now)
        let result = logEntries
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

    /// Shared Shadowsocks UDP sessions keyed by configuration id. One session
    /// services every UDP flow for a given SS configuration, so all
    /// destinations share a sessionID + upstream socket.
    var ssUDPSessions: [UUID: ShadowsocksUDPSession] = [:]

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

    // MARK: - Shadowsocks UDP Sessions

    /// Returns the shared SS UDP session for `configuration`, creating one on
    /// first use. Must be called on `lwipQueue`.
    ///
    /// The session lives across individual UDP flows so that one sessionID
    /// and one upstream socket serve every destination — which is what
    /// restores full-cone NAT and avoids per-flow session churn. A session
    /// that has reached a terminal (failed/cancelled) state is evicted and
    /// replaced transparently.
    func shadowsocksUDPSession(for configuration: ProxyConfiguration) -> Result<ShadowsocksUDPSession, Error> {
        if let existing = ssUDPSessions[configuration.id], existing.isUsable {
            return .success(existing)
        }
        ssUDPSessions.removeValue(forKey: configuration.id)

        guard let method = configuration.ssMethod,
              let cipher = ShadowsocksCipher(method: method) else {
            return .failure(ShadowsocksError.invalidMethod(configuration.ssMethod ?? "nil"))
        }
        guard let password = configuration.ssPassword else {
            return .failure(ProxyError.protocolError("Shadowsocks password not set"))
        }

        let mode: ShadowsocksUDPSession.Mode
        if cipher.isSS2022 {
            guard let pskList = ShadowsocksKeyDerivation.decodePSKList(password: password, keySize: cipher.keySize) else {
                return .failure(ShadowsocksError.invalidPSK)
            }
            if cipher == .blake3chacha20poly1305 {
                mode = .ss2022ChaCha(psk: pskList.last!)
            } else {
                mode = .ss2022AES(cipher: cipher, pskList: pskList)
            }
        } else {
            let masterKey = ShadowsocksKeyDerivation.deriveKey(password: password, keySize: cipher.keySize)
            mode = .legacy(cipher: cipher, masterKey: masterKey)
        }

        let session = ShadowsocksUDPSession(
            mode: mode,
            serverHost: configuration.serverAddress,
            serverPort: configuration.serverPort,
            delegateQueue: lwipQueue
        )
        ssUDPSessions[configuration.id] = session
        return .success(session)
    }

    /// Cancels and forgets every SS UDP session. Must be called on `lwipQueue`.
    /// Called on stack shutdown, configuration switch, and device wake (the
    /// kernel tears down our UDP sockets during sleep).
    func purgeShadowsocksUDPSessions() {
        for (_, session) in ssUDPSessions {
            session.cancel()
        }
        ssUDPSessions.removeAll()
    }

    // MARK: - Runtime Configuration

    func configureRuntime(for configuration: ProxyConfiguration) {
        loadIPv6Settings()
        loadBypassCountry()
        loadEncryptedDNSSetting()
        loadProxyModeSetting()
        loadHideVPNIconSetting()
        loadBlockQUICSetting()
        loadMITMSetting()

        // The first hop is the only domain the NE itself re-resolves frequently
        // (subsequent chain hops are resolved by upstream proxy servers). Mark
        // it active so ProxyDNSCache returns stale IPs immediately on TTL
        // expiry and refreshes in the background, keeping reconnects snappy.
        ProxyDNSResolver.shared.setActiveProxyDomain(Self.firstHopAddress(for: configuration))

        if Self.shouldUseVisionMux(configuration) {
            muxManager = MuxManager(configuration: configuration, lwipQueue: lwipQueue)
        } else {
            muxManager = nil
        }

        if proxyMode != .global {
            domainRouter.loadRoutingConfiguration()
        } else {
            domainRouter.reset()
        }
    }

    /// The serverAddress of the first proxy the NE dials directly. For chain
    /// configurations that's `chain[0]`; otherwise it's the exit proxy itself.
    private static func firstHopAddress(for configuration: ProxyConfiguration) -> String {
        configuration.chain?.first?.serverAddress ?? configuration.serverAddress
    }

    static func shouldUseVisionMux(_ configuration: ProxyConfiguration) -> Bool {
        configuration.outboundProtocol == .vless &&
        configuration.muxEnabled &&
        (configuration.flow == "xtls-rprx-vision" || configuration.flow == "xtls-rprx-vision-udp443")
    }

    /// Reads IPv6 settings from app group UserDefaults.
    private func loadIPv6Settings() {
        ipv6DNSEnabled = AWCore.getIPv6DNSEnabled()
    }

    /// Reads the bypass country code from app group UserDefaults.
    private func loadBypassCountry() {
        bypassCountryCode = AWCore.getBypassCountryCode()
    }

    /// Reads encrypted DNS settings from app group UserDefaults.
    private func loadEncryptedDNSSetting() {
        encryptedDNSEnabled = AWCore.getEncryptedDNSEnabled()
        encryptedDNSProtocol = AWCore.getEncryptedDNSProtocol()
        encryptedDNSServer = AWCore.getEncryptedDNSServer()
    }

    private func loadProxyModeSetting() {
        proxyMode = AWCore.getProxyMode()
    }

    private func loadHideVPNIconSetting() {
        hideVPNIcon = AWCore.getHideVPNIcon()
    }

    private func loadBlockQUICSetting() {
        blockQUICEnabled = AWCore.getBlockQUICEnabled()
    }

    /// Loads the MITM master toggle and rebuilds the in-memory rewrite
    /// policy. Called from ``configureRuntime`` and from the
    /// ``mitmChanged`` Darwin notification observer.
    func loadMITMSetting() {
        let snapshot = MITMSnapshot.load()
        mitmEnabled = snapshot.enabled
        if snapshot.enabled {
            mitmPolicy.load(ruleSets: snapshot.ruleSets)
        } else {
            mitmPolicy.reset()
        }
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
