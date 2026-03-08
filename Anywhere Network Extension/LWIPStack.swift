//
//  LWIPStack.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation
import NetworkExtension
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "LWIPStack")

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
    private let outputQueue = DispatchQueue(label: "com.argsment.Anywhere.output")

    private var packetFlow: NEPacketTunnelFlow?
    private(set) var configuration: ProxyConfiguration?

    private static let ipv4Proto = NSNumber(value: AF_INET)
    private static let ipv6Proto = NSNumber(value: AF_INET6)
    private var outputPackets: [Data] = []
    private var outputProtocols: [NSNumber] = []
    private var outputFlushScheduled = false

    // --- Settings (read from App Group UserDefaults) ---
    // These are loaded at start/restart and live-reloaded via Darwin notification.
    //
    // Setting          │ Where it takes effect             │ On change
    // ─────────────────┼───────────────────────────────────┼──────────────────────────────
    // ipv6Enabled      │ Tunnel settings (IPv6 routes),    │ Reapply tunnel settings +
    //                  │ lwIP stack (fake IPv6 pool)       │ stack restart
    // dohEnabled       │ lwIP DNS interception (DDR block) │ Stack restart (forces DNS
    //                  │                                   │ re-discovery with new DDR policy)
    // bypassCountry    │ lwIP per-connection bypass check  │ Stack restart
    // routingRules     │ DomainRouter (connection-time)     │ Stack restart (closes connections
    //                  │                                   │ using outdated proxy configurations;
    //                  │                                   │ FakeIPPool preserved)

    private(set) var ipv6Enabled: Bool = false
    private(set) var dohEnabled: Bool = false
    private var running = false

    // lwIP periodic timeout timer
    private var timeoutTimer: DispatchSourceTimer?

    /// GeoIP database for country-based bypass (loaded once, reused across configuration switches).
    private var geoIPDatabase: GeoIPDatabase?

    /// Packed UInt16 country code to bypass (0 = disabled).
    private(set) var bypassCountry: UInt16 = 0

    /// Global traffic counters (bytes through the tunnel).
    /// Incremented on lwipQueue / outputQueue; reads from other queues are safe on 64-bit ARM.
    private(set) var totalBytesIn: Int64 = 0
    private(set) var totalBytesOut: Int64 = 0

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
    private var udpCleanupTimer: DispatchSourceTimer?
    private let maxUDPFlows = 200
    private let udpIdleTimeout: CFAbsoluteTime = 60

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

    // MARK: - GeoIP Bypass

    /// Returns true if traffic to the given host should bypass the tunnel.
    /// Checks proxy server addresses first (prevents routing loops after config switch),
    /// then falls back to GeoIP country-based bypass.
    func shouldBypass(host: String) -> Bool {
        if isProxyServerAddress(host) { return true }
        guard bypassCountry != 0 else { return false }
        return geoIPDatabase?.lookup(host) == bypassCountry
    }

    /// Returns true if the given host matches any proxy server address in the current
    /// configuration. Prevents routing loops when the server's IP enters the tunnel
    /// (e.g. after a configuration switch where the route exclusion is stale).
    private func isProxyServerAddress(_ host: String) -> Bool {
        guard let config = configuration else { return false }
        if host == config.serverAddress || host == config.resolvedIP { return true }
        if let chain = config.chain {
            for proxy in chain {
                if host == proxy.serverAddress || host == proxy.resolvedIP { return true }
            }
        }
        return false
    }

    /// Reads the bypass country code from app group UserDefaults and converts to UInt16.
    private func loadBypassCountry() {
        let code = AWCore.userDefaults.string(forKey: "bypassCountryCode") ?? ""
        bypassCountry = code.isEmpty ? 0 : GeoIPDatabase.packCountryCode(code)
        if bypassCountry != 0 {
            logger.info("[LWIPStack] Bypass country: \(code, privacy: .public)")
        }
    }

    /// Reads the DoH setting from app group UserDefaults.
    private func loadDoHSetting() {
        dohEnabled = AWCore.userDefaults.bool(forKey: "dohEnabled")
    }

    // MARK: - Lifecycle

    /// Starts the lwIP stack and begins reading packets from the tunnel.
    ///
    /// - Parameters:
    ///   - packetFlow: The tunnel's packet flow for reading/writing IP packets.
    ///   - configuration: The VLESS proxy configuration.
    func start(packetFlow: NEPacketTunnelFlow,
               configuration: ProxyConfiguration,
               ipv6Enabled: Bool = false) {
        logger.info("[LWIPStack] Starting, ipv6Enabled=\(ipv6Enabled)")
        LWIPStack.shared = self
        self.packetFlow = packetFlow
        self.configuration = configuration
        self.ipv6Enabled = ipv6Enabled

        lwipQueue.async { [self] in
            self.running = true
            self.totalBytesIn = 0
            self.totalBytesOut = 0

            // Load GeoIP database once (reused across switchConfiguration)
            if self.geoIPDatabase == nil {
                self.geoIPDatabase = GeoIPDatabase()
            }
            self.loadBypassCountry()
            self.loadDoHSetting()

            // Create MuxManager when Vision + Mux is active (matches Xray-core auto-mux for UDP)
            // Mux is not supported with Shadowsocks
            if configuration.outboundProtocol == .vless && configuration.muxEnabled && (configuration.flow == "xtls-rprx-vision" || configuration.flow == "xtls-rprx-vision-udp443") {
                self.muxManager = MuxManager(configuration: configuration, lwipQueue: self.lwipQueue)
            }

            self.domainRouter.loadRoutingConfiguration()
            self.registerCallbacks()
            lwip_bridge_init()
            self.startTimeoutTimer()
            self.startUDPCleanupTimer()
            self.startReadingPackets()
            logger.info("[LWIPStack] Started, mux=\(self.muxManager != nil), bypass=\(self.bypassCountry != 0), doh=\(self.dohEnabled)")
        }

        startObservingSettings()
    }

    /// Stops the lwIP stack and closes all active flows.
    func stop() {
        logger.info("[LWIPStack] Stopping")
        stopObservingSettings()
        lwipQueue.sync { [self] in
            self.running = false
            self.shutdownInternal()
            self.fakeIPPool.reset()
        }

        self.packetFlow = nil
        self.configuration = nil
        LWIPStack.shared = nil
    }

    /// Switches to a new configuration, tearing down all active connections.
    ///
    /// Shuts down the lwIP stack and all VLESS connections, then restarts
    /// with the new configuration using the existing packet flow.
    func switchConfiguration(_ newConfiguration: ProxyConfiguration, ipv6Enabled: Bool? = nil) {
        logger.info("[LWIPStack] Switching configuration")
        lwipQueue.async { [self] in
            self.restartStack(configuration: newConfiguration,
                              ipv6Enabled: ipv6Enabled ?? self.ipv6Enabled)
        }
    }

    /// Shuts down the lwIP stack and all active flows. Must be called on `lwipQueue`.
    /// Does NOT change `running` — callers manage it:
    /// - `stop()` sets `running = false` before calling (kills the packet read loop).
    /// - `restartStack()` leaves `running = true` (existing read loop continues).
    ///
    /// Note: Does NOT reset FakeIPPool. Callers handle pool lifecycle:
    /// - `stop()` calls `fakeIPPool.reset()` (full teardown, no reconnections expected).
    /// - `restartStack()` preserves pool as-is (routing decisions are made at connection time).
    private func shutdownInternal() {
        self.totalBytesIn = 0
        self.totalBytesOut = 0

        self.timeoutTimer?.cancel()
        self.timeoutTimer = nil
        self.udpCleanupTimer?.cancel()
        self.udpCleanupTimer = nil

        self.outputPackets.removeAll(keepingCapacity: true)
        self.outputProtocols.removeAll(keepingCapacity: true)
        self.outputFlushScheduled = false

        self.muxManager?.closeAll()
        self.muxManager = nil

        let flowCount = self.udpFlows.count
        for (_, flow) in self.udpFlows {
            flow.close()
        }
        self.udpFlows.removeAll()

        lwip_bridge_shutdown()
        logger.info("[LWIPStack] Shutdown complete, closed \(flowCount) UDP flows")
    }

    /// Tears down all connections and restarts the lwIP stack. Must be called on `lwipQueue`.
    /// `running` stays `true` so the existing `readPackets` loop continues uninterrupted —
    /// packets queued on lwipQueue during reinit are processed after `lwip_bridge_init()`.
    /// FakeIPPool is preserved across restarts — since all DNS queries get fake IPs and
    /// routing decisions are made at connection time, cached fake IPs remain valid.
    private func restartStack(configuration: ProxyConfiguration, ipv6Enabled: Bool) {
        shutdownInternal()

        self.configuration = configuration
        self.ipv6Enabled = ipv6Enabled
        self.loadBypassCountry()
        self.loadDoHSetting()

        if configuration.outboundProtocol == .vless && configuration.muxEnabled && (configuration.flow == "xtls-rprx-vision" || configuration.flow == "xtls-rprx-vision-udp443") {
            self.muxManager = MuxManager(configuration: configuration, lwipQueue: self.lwipQueue)
        }

        self.domainRouter.loadRoutingConfiguration()
        self.registerCallbacks()
        lwip_bridge_init()
        self.startTimeoutTimer()
        self.startUDPCleanupTimer()
        // Note: startReadingPackets() is NOT called here — the existing read loop
        // (started in start()) continues because `running` was never set to false.
        logger.info("[LWIPStack] Restarted, mux=\(self.muxManager != nil), bypass=\(self.bypassCountry != 0), doh=\(self.dohEnabled), ipv6=\(self.ipv6Enabled)")
    }

    // MARK: - Settings Observation
    //
    // Two Darwin notifications are observed. Both trigger a full stack restart
    // (shutdownInternal → restartStack), which closes all TCP/UDP connections
    // and re-reads settings. FakeIPPool is preserved — routing decisions are
    // made at connection time, so rule changes take effect immediately.
    //
    // 1. "settingsChanged" — posted by SettingsView when ipv6/bypass/doh toggles change.
    //    IPv6 additionally re-applies tunnel network settings (routes + DNS servers).
    //
    // 2. "routingChanged" — posted by RuleSetListView when routing rule assignments change.

    /// Registers Darwin notification observers for cross-process settings changes.
    private func startObservingSettings() {
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            Unmanaged.passUnretained(self).toOpaque(),
            { _, observer, _, _, _ in
                guard let observer else { return }
                let stack = Unmanaged<LWIPStack>.fromOpaque(observer).takeUnretainedValue()
                stack.handleSettingsChanged()
            },
            "com.argsment.Anywhere.settingsChanged" as CFString,
            nil,
            .deliverImmediately
        )

        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            Unmanaged.passUnretained(self).toOpaque(),
            { _, observer, _, _, _ in
                guard let observer else { return }
                let stack = Unmanaged<LWIPStack>.fromOpaque(observer).takeUnretainedValue()
                stack.handleRoutingChanged()
            },
            "com.argsment.Anywhere.routingChanged" as CFString,
            nil,
            .deliverImmediately
        )
    }

    private func stopObservingSettings() {
        CFNotificationCenterRemoveEveryObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            Unmanaged.passUnretained(self).toOpaque()
        )
    }

    /// Handles the "settingsChanged" notification (ipv6/bypass/doh toggles).
    /// Compares current values against UserDefaults and restarts the stack if changed.
    /// Stack restart closes all connections, clears FakeIPPool, and re-reads all settings.
    private func handleSettingsChanged() {
        lwipQueue.async { [self] in
            guard self.running, let config = self.configuration else { return }

            let newIPv6 = AWCore.userDefaults.bool(forKey: "ipv6Enabled")
            let newBypassCode = AWCore.userDefaults.string(forKey: "bypassCountryCode") ?? ""
            let newBypass = newBypassCode.isEmpty ? 0 : GeoIPDatabase.packCountryCode(newBypassCode)
            let newDoH = AWCore.userDefaults.bool(forKey: "dohEnabled")

            let ipv6Changed = newIPv6 != self.ipv6Enabled
            let bypassChanged = newBypass != self.bypassCountry
            let dohChanged = newDoH != self.dohEnabled

            guard ipv6Changed || bypassChanged || dohChanged else { return }

            // IPv6 toggle affects tunnel network settings (IPv6 routes + DNS servers).
            // Must re-apply via PacketTunnelProvider before restarting the stack.
            if ipv6Changed {
                self.onTunnelSettingsNeedReapply?()
            }

            logger.info("[LWIPStack] Settings changed, restarting (bypass=\(newBypass != 0), ipv6=\(newIPv6), doh=\(newDoH))")
            self.restartStack(configuration: config, ipv6Enabled: newIPv6)
        }
    }

    /// Handles the "routingChanged" notification (routing rule assignments changed).
    /// Restarts the stack to close all connections using outdated proxy configurations,
    /// rebuilds the FakeIPPool, and reloads DomainRouter rules from routing.json.
    /// Note: Do NOT call onTunnelSettingsNeedReapply here — setTunnelNetworkSettings
    /// should only be triggered by IPv6 changes (which affect tunnel routes and DNS servers).
    /// Routing changes do not alter NEPacketTunnelNetworkSettings.
    private func handleRoutingChanged() {
        lwipQueue.async { [self] in
            guard self.running, let config = self.configuration else { return }
            logger.info("[LWIPStack] Routing rules changed, restarting")
            self.restartStack(configuration: config, ipv6Enabled: self.ipv6Enabled)
        }
    }

    // MARK: - Callback Registration

    /// Registers C callbacks that route lwIP events through ``shared``.
    private func registerCallbacks() {
        // Output: lwIP → tunnel packet flow (batched)
        // Accumulates output packets during synchronous lwip_bridge_input processing,
        // then flushes them all in a single writePackets call. This reduces kernel
        // crossings from N per batch to 1, speeding up ACK delivery to the OS TCP
        // stack and improving upload throughput.
        lwip_bridge_set_output_fn { data, len, isIPv6 in
            guard let shared = LWIPStack.shared, let data else { return }
            let byteCount = Int(len)
            shared.totalBytesIn += Int64(byteCount)
            shared.outputPackets.append(Data(bytes: data, count: byteCount))
            shared.outputProtocols.append(isIPv6 != 0 ? LWIPStack.ipv6Proto : LWIPStack.ipv4Proto)
            if !shared.outputFlushScheduled {
                shared.outputFlushScheduled = true
                shared.lwipQueue.async {
                    shared.flushOutputPackets()
                }
            }
        }

        // TCP accept: create a new LWIPTCPConnection for each incoming connection
        lwip_bridge_set_tcp_accept_fn { srcIP, srcPort, dstIP, dstPort, isIPv6, pcb in
            guard let shared = LWIPStack.shared,
                  let pcb, let dstIP,
                  let defaultConfiguration = shared.configuration else {
                logger.error("[LWIPStack] tcp_accept: guard failed")
                return nil
            }

            if isIPv6 != 0 && !shared.ipv6Enabled {
                return nil
            }

            let dstIPString = LWIPStack.ipAddrToString(dstIP, isIPv6: isIPv6 != 0)

            var dstHost = dstIPString
            var connectionConfiguration = defaultConfiguration
            var forceBypass = false

            switch shared.resolveFakeIP(dstIPString, dstPort: dstPort, proto: "TCP") {
            case .passthrough:
                break
            case .resolved(let domain, let configOverride, let bypass):
                dstHost = domain
                if let config = configOverride { connectionConfiguration = config }
                forceBypass = bypass
            case .drop, .unreachable:
                return nil
            }

            let connection = LWIPTCPConnection(pcb: pcb, dstHost: dstHost, dstPort: dstPort,
                                          configuration: connectionConfiguration,
                                          forceBypass: forceBypass,
                                          lwipQueue: shared.lwipQueue)
            return Unmanaged.passRetained(connection).toOpaque()
        }

        // TCP recv: deliver data to the connection
        lwip_bridge_set_tcp_recv_fn { connection, data, len in
            guard let connection else {
                logger.error("[LWIPStack] tcp_recv: connection is nil")
                return
            }
            let tcpConnection = Unmanaged<LWIPTCPConnection>.fromOpaque(connection).takeUnretainedValue()
            if let data, len > 0 {
                tcpConnection.handleReceivedData(Data(bytes: data, count: Int(len)))
            } else {
                tcpConnection.handleRemoteClose()
            }
        }

        // TCP sent: notify the connection of acknowledged bytes
        lwip_bridge_set_tcp_sent_fn { connection, len in
            guard let connection else { return }
            let tcpConnection = Unmanaged<LWIPTCPConnection>.fromOpaque(connection).takeUnretainedValue()
            tcpConnection.handleSent(len: len)
        }

        // TCP error: PCB is already freed by lwIP — release our reference
        lwip_bridge_set_tcp_err_fn { connection, err in
            guard let connection else {
                logger.error("[LWIPStack] tcp_err: connection is nil, err=\(err)")
                return
            }
            let tcpConnection = Unmanaged<LWIPTCPConnection>.fromOpaque(connection).takeRetainedValue()
            tcpConnection.handleError(err: err)
        }

        // UDP recv: route datagrams to per-flow handlers
        lwip_bridge_set_udp_recv_fn { srcIP, srcPort, dstIP, dstPort, isIPv6, data, len in
            guard let shared = LWIPStack.shared,
                  let srcIP, let dstIP, let data else { return }

            if isIPv6 != 0 && !shared.ipv6Enabled {
                return
            }

            let payload = Data(bytes: data, count: Int(len))

            // DNS interception: intercept port-53 A/AAAA queries with fake-IP responses
            if dstPort == 53 {
                if shared.handleDNSQuery(payload: payload,
                                          srcIP: srcIP, srcPort: srcPort,
                                          dstIP: dstIP, dstPort: dstPort,
                                          isIPv6: isIPv6 != 0) {
                    return  // Fake response sent, no flow needed
                }
                // Non-A/AAAA query — fall through, create normal UDP flow to proxy DNS
            }

            let srcHost = LWIPStack.ipAddrToString(srcIP, isIPv6: isIPv6 != 0)
            let dstIPString = LWIPStack.ipAddrToString(dstIP, isIPv6: isIPv6 != 0)

            // Fast path: deliver to an existing flow without re-resolving the fake IP.
            // The flow already has the resolved domain from when it was created.
            // This avoids dropping packets for long-lived flows (e.g. QUIC) whose
            // fake-IP pool entries may have been evicted by newer DNS allocations.
            let flowKey = UDPFlowKey(srcHost: srcHost, srcPort: srcPort, dstHost: dstIPString, dstPort: dstPort)
            if let flow = shared.udpFlows[flowKey] {
                flow.handleReceivedData(payload, payloadLength: Int(len))
                return
            }

            // New flow — resolve fake IP to domain and determine routing
            var dstHost = dstIPString
            guard let defaultConfiguration = shared.configuration else { return }
            var flowConfiguration = defaultConfiguration
            var forceBypass = false

            switch shared.resolveFakeIP(dstIPString, dstPort: dstPort, proto: "UDP") {
            case .passthrough:
                break
            case .resolved(let domain, let configOverride, let bypass):
                dstHost = domain
                if let config = configOverride { flowConfiguration = config }
                forceBypass = bypass
            case .drop:
                return
            case .unreachable:
                shared.sendICMPPortUnreachable(
                    srcIP: srcIP, srcPort: srcPort,
                    dstIP: dstIP, dstPort: dstPort,
                    isIPv6: isIPv6 != 0,
                    udpPayloadLength: Int(len))
                return
            }

            guard shared.udpFlows.count < shared.maxUDPFlows else {
                logger.error("[LWIPStack] UDP max flows reached (\(shared.maxUDPFlows)), dropping \(flowKey, privacy: .public)")
                return
            }

            let addrSize = isIPv6 != 0 ? 16 : 4
            let srcIPData = Data(bytes: srcIP, count: addrSize)
            let dstIPData = Data(bytes: dstIP, count: addrSize)

            let flow = LWIPUDPFlow(
                flowKey: flowKey,
                srcHost: srcHost, srcPort: srcPort,
                dstHost: dstHost, dstPort: dstPort,
                srcIPData: srcIPData, dstIPData: dstIPData,
                isIPv6: isIPv6 != 0,
                configuration: flowConfiguration,
                forceBypass: forceBypass,
                lwipQueue: shared.lwipQueue
            )
            shared.udpFlows[flowKey] = flow
            flow.handleReceivedData(payload, payloadLength: Int(len))
        }
    }

    // MARK: - Fake-IP Resolution

    /// Result of resolving a fake IP to its domain and routing configuration.
    enum FakeIPResolution {
        /// IP is not a fake IP — use original IP as host, default config, no bypass.
        case passthrough
        /// Resolved to a domain with optional config override and bypass flag.
        case resolved(domain: String, configOverride: ProxyConfiguration?, forceBypass: Bool)
        /// Connection should be dropped (rejected by rule).
        case drop
        /// Fake IP not in pool (stale from previous session) — drop and signal unreachable.
        case unreachable
    }

    /// Resolves a destination IP through the fake-IP pool and domain router.
    /// Shared by TCP accept and UDP recv callbacks.
    func resolveFakeIP(_ ip: String, dstPort: UInt16, proto: String) -> FakeIPResolution {
        guard FakeIPPool.isFakeIP(ip) else { return .passthrough }

        guard let entry = fakeIPPool.lookup(ip: ip) else {
            return .unreachable
        }

        if let action = domainRouter.matchDomain(entry.domain) {
            switch action {
            case .direct:
                return .resolved(domain: entry.domain, configOverride: nil, forceBypass: true)
            case .reject:
                logger.info("[FakeIP] \(proto, privacy: .public) rejected for \(entry.domain, privacy: .public)")
                return .drop
            case .proxy(let id):
                let config = domainRouter.resolveConfiguration(action: action)
                if config == nil {
                    logger.warning("[FakeIP] \(proto, privacy: .public) proxy config \(id) not found for \(entry.domain, privacy: .public)")
                }
                return .resolved(domain: entry.domain, configOverride: config, forceBypass: false)
            }
        }

        return .resolved(domain: entry.domain, configOverride: nil, forceBypass: false)
    }

    // MARK: - DNS Interception (Fake-IP)
    //
    // DNS queries arriving on UDP port 53 are intercepted here before creating any flow.
    // Two types of interception:
    //
    // 1. DDR blocking: When DoH is disabled, queries for "_dns.resolver.arpa" (RFC 9462)
    //    get a NODATA response. This prevents the system from discovering that the DNS
    //    server supports DoH and auto-upgrading, which would move all DNS to port 443
    //    and bypass our port-53 interception entirely.
    //
    // 2. Fake-IP for ALL A/AAAA queries: Every domain gets a synthetic fake IP response.
    //    When TCP/UDP connections later arrive at the fake IP, we look up the original
    //    domain and make routing decisions (direct/proxy) at connection time by checking
    //    DomainRouter. This ensures routing rule changes take effect immediately without
    //    waiting for OS DNS cache expiry.

    /// Intercepts a DNS query. Returns true if handled (no UDP flow needed).
    private func handleDNSQuery(payload: Data,
                                 srcIP: UnsafeRawPointer, srcPort: UInt16,
                                 dstIP: UnsafeRawPointer, dstPort: UInt16,
                                 isIPv6: Bool) -> Bool {
        // Parse domain + QTYPE
        guard let parsed = payload.withUnsafeBytes({ ptr -> (domain: String, qtype: UInt16)? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.parseQuery(UnsafeBufferPointer(start: base, count: ptr.count))
        }) else { return false }

        let domain = parsed.domain.lowercased()
        let qtype = parsed.qtype

        // Block DDR (Discovery of Designated Resolvers, RFC 9462) when DoH is disabled
        // to prevent the system from auto-upgrading to DNS-over-HTTPS, which bypasses
        // port-53 interception needed for fake-IP domain routing.
        if !dohEnabled, domain == "_dns.resolver.arpa" {
            return sendNODATA(payload: payload, srcIP: srcIP, srcPort: srcPort,
                              dstIP: dstIP, dstPort: dstPort, isIPv6: isIPv6, qtype: qtype)
        }

        // Only intercept A (1) and AAAA (28) queries; let MX/SRV/etc. pass through
        guard qtype == 1 || qtype == 28 else { return false }

        // Reject: return NODATA so the domain gets no IP at all
        if let action = domainRouter.matchDomain(domain), case .reject = action {
            logger.info("[FakeIP] Rejected DNS for \(domain, privacy: .public)")
            return sendNODATA(payload: payload, srcIP: srcIP, srcPort: srcPort,
                              dstIP: dstIP, dstPort: dstPort, isIPv6: isIPv6, qtype: qtype)
        }

        // Intercept ALL A/AAAA queries with fake IPs.
        // Routing decisions (direct/proxy/specific proxy) are made at connection time
        // by checking domainRouter, so rule changes take effect immediately without
        // waiting for DNS cache expiry.
        let offset = fakeIPPool.allocate(domain: domain)

        // Build fake IP bytes for the response
        var fakeIPBytes: [UInt8]?
        if qtype == 1 {
            // A query → fake IPv4
            let ipv4 = FakeIPPool.ipv4Bytes(offset: offset)
            fakeIPBytes = [ipv4.0, ipv4.1, ipv4.2, ipv4.3]
        } else if qtype == 28, ipv6Enabled {
            // AAAA query + IPv6 enabled → fake IPv6
            fakeIPBytes = FakeIPPool.ipv6Bytes(offset: offset)
        }
        // else: AAAA query + IPv6 disabled → fakeIPBytes stays nil → NODATA response

        // Generate DNS response
        guard let responseData = payload.withUnsafeBytes({ ptr -> Data? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.generateResponse(
                query: UnsafeBufferPointer(start: base, count: ptr.count),
                fakeIP: fakeIPBytes, qtype: qtype)
        }) else { return false }
        responseData.withUnsafeBytes { dataPtr in
            guard let dataBase = dataPtr.baseAddress else { return }
            lwip_bridge_udp_sendto(
                dstIP, dstPort,     // original dst becomes response src
                srcIP, srcPort,     // original src becomes response dst
                isIPv6 ? 1 : 0,
                dataBase, Int32(responseData.count)
            )
        }

        return true
    }

    /// Sends a NODATA DNS response (ANCOUNT=0) for the given query.
    private func sendNODATA(payload: Data,
                             srcIP: UnsafeRawPointer, srcPort: UInt16,
                             dstIP: UnsafeRawPointer, dstPort: UInt16,
                             isIPv6: Bool, qtype: UInt16) -> Bool {
        guard let responseData = payload.withUnsafeBytes({ ptr -> Data? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.generateResponse(
                query: UnsafeBufferPointer(start: base, count: ptr.count),
                fakeIP: nil, qtype: qtype)
        }) else { return false }

        responseData.withUnsafeBytes { dataPtr in
            guard let dataBase = dataPtr.baseAddress else { return }
            lwip_bridge_udp_sendto(dstIP, dstPort, srcIP, srcPort,
                                    isIPv6 ? 1 : 0, dataBase, Int32(responseData.count))
        }
        logger.info("[FakeIP] Blocked DDR query (qtype=\(qtype))")
        return true
    }

    // MARK: - ICMP Port Unreachable
    //
    // Sent when UDP arrives at a stale fake IP no longer in the pool (e.g. from a
    // previous VPN session). The ICMP response causes QUIC/UDP clients to abandon
    // the stale connection and re-resolve DNS, instead of retrying indefinitely.

    /// Crafts and queues an ICMP Destination Unreachable (Port Unreachable) response.
    /// Must be called on lwipQueue.
    private func sendICMPPortUnreachable(
        srcIP: UnsafeRawPointer, srcPort: UInt16,
        dstIP: UnsafeRawPointer, dstPort: UInt16,
        isIPv6: Bool,
        udpPayloadLength: Int
    ) {
        let packet: Data
        let proto: NSNumber
        if isIPv6 {
            packet = buildICMPv6PortUnreachable(
                srcIP: srcIP, srcPort: srcPort,
                dstIP: dstIP, dstPort: dstPort,
                udpPayloadLength: udpPayloadLength)
            proto = Self.ipv6Proto
        } else {
            packet = buildICMPv4PortUnreachable(
                srcIP: srcIP, srcPort: srcPort,
                dstIP: dstIP, dstPort: dstPort,
                udpPayloadLength: udpPayloadLength)
            proto = Self.ipv4Proto
        }
        outputPackets.append(packet)
        outputProtocols.append(proto)
        if !outputFlushScheduled {
            outputFlushScheduled = true
            lwipQueue.async { [self] in
                self.flushOutputPackets()
            }
        }
    }

    /// Builds an IPv4 ICMP Destination Unreachable (Type 3, Code 3) packet.
    /// Contains a reconstructed original IPv4+UDP header per RFC 792.
    private func buildICMPv4PortUnreachable(
        srcIP: UnsafeRawPointer, srcPort: UInt16,
        dstIP: UnsafeRawPointer, dstPort: UInt16,
        udpPayloadLength: Int
    ) -> Data {
        // Outer IPv4 (20) + ICMP header (8) + inner IPv4 (20) + UDP header (8) = 56
        let packetLen = 56
        var packet = Data(count: packetLen)
        packet.withUnsafeMutableBytes { raw in
            let p = raw.bindMemory(to: UInt8.self).baseAddress!

            // --- Outer IPv4 header (src=fake IP, dst=sender) ---
            p[0] = 0x45                                     // Version 4, IHL 5
            p[1] = 0x00                                     // TOS
            p[2] = UInt8(packetLen >> 8)                    // Total length
            p[3] = UInt8(packetLen & 0xFF)
            p[4] = 0; p[5] = 0                              // Identification
            p[6] = 0; p[7] = 0                              // Flags + Fragment offset
            p[8] = 64                                        // TTL
            p[9] = 1                                         // Protocol: ICMP
            p[10] = 0; p[11] = 0                             // Checksum (below)
            memcpy(p + 12, dstIP, 4)                         // Src = fake IP
            memcpy(p + 16, srcIP, 4)                         // Dst = sender

            // IPv4 header checksum
            var sum: UInt32 = 0
            for i in stride(from: 0, to: 20, by: 2) {
                sum += UInt32(p[i]) << 8 | UInt32(p[i + 1])
            }
            while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16) }
            let ipCksum = ~UInt16(sum)
            p[10] = UInt8(ipCksum >> 8); p[11] = UInt8(ipCksum & 0xFF)

            // --- ICMP header (Type 3 = Dest Unreachable, Code 3 = Port Unreachable) ---
            p[20] = 3; p[21] = 3                             // Type, Code
            p[22] = 0; p[23] = 0                             // Checksum (below)
            p[24] = 0; p[25] = 0; p[26] = 0; p[27] = 0     // Unused

            // --- Reconstructed original IPv4 header ---
            let udpTotalLen = 8 + udpPayloadLength
            let innerTotalLen = 20 + udpTotalLen
            p[28] = 0x45; p[29] = 0x00                      // Version 4, IHL 5, TOS
            p[30] = UInt8((innerTotalLen >> 8) & 0xFF)       // Total length
            p[31] = UInt8(innerTotalLen & 0xFF)
            p[32] = 0; p[33] = 0                             // Identification
            p[34] = 0; p[35] = 0                             // Flags + Fragment offset
            p[36] = 64; p[37] = 17                           // TTL, Protocol: UDP
            p[38] = 0; p[39] = 0                             // Checksum (0 OK in ICMP payload)
            memcpy(p + 40, srcIP, 4)                         // Src = original sender
            memcpy(p + 44, dstIP, 4)                         // Dst = fake IP

            // --- First 8 bytes of original UDP ---
            p[48] = UInt8(srcPort >> 8); p[49] = UInt8(srcPort & 0xFF)
            p[50] = UInt8(dstPort >> 8); p[51] = UInt8(dstPort & 0xFF)
            p[52] = UInt8((udpTotalLen >> 8) & 0xFF)
            p[53] = UInt8(udpTotalLen & 0xFF)
            p[54] = 0; p[55] = 0                             // UDP checksum

            // ICMP checksum (over ICMP header + data, offset 20..55)
            sum = 0
            for i in stride(from: 20, to: packetLen, by: 2) {
                sum += UInt32(p[i]) << 8 | UInt32(p[i + 1])
            }
            while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16) }
            let icmpCksum = ~UInt16(sum)
            p[22] = UInt8(icmpCksum >> 8); p[23] = UInt8(icmpCksum & 0xFF)
        }
        return packet
    }

    /// Builds an IPv6 ICMPv6 Destination Unreachable (Type 1, Code 4) packet.
    /// Contains a reconstructed original IPv6+UDP header per RFC 4443.
    private func buildICMPv6PortUnreachable(
        srcIP: UnsafeRawPointer, srcPort: UInt16,
        dstIP: UnsafeRawPointer, dstPort: UInt16,
        udpPayloadLength: Int
    ) -> Data {
        // Outer IPv6 (40) + ICMPv6 header (8) + inner IPv6 (40) + UDP header (8) = 96
        let icmpLen = 56  // 8 + 40 + 8
        let packetLen = 40 + icmpLen
        var packet = Data(count: packetLen)
        packet.withUnsafeMutableBytes { raw in
            let p = raw.bindMemory(to: UInt8.self).baseAddress!

            // --- Outer IPv6 header (src=fake IP, dst=sender) ---
            p[0] = 0x60; p[1] = 0; p[2] = 0; p[3] = 0      // Version 6, TC, Flow Label
            p[4] = UInt8(icmpLen >> 8)                        // Payload length
            p[5] = UInt8(icmpLen & 0xFF)
            p[6] = 58                                         // Next Header: ICMPv6
            p[7] = 64                                         // Hop Limit
            memcpy(p + 8, dstIP, 16)                          // Src = fake IP
            memcpy(p + 24, srcIP, 16)                         // Dst = sender

            // --- ICMPv6 header (Type 1 = Dest Unreachable, Code 4 = Port Unreachable) ---
            p[40] = 1; p[41] = 4                              // Type, Code
            p[42] = 0; p[43] = 0                              // Checksum (below)
            p[44] = 0; p[45] = 0; p[46] = 0; p[47] = 0      // Unused

            // --- Reconstructed original IPv6 header ---
            let udpTotalLen = 8 + udpPayloadLength
            p[48] = 0x60; p[49] = 0; p[50] = 0; p[51] = 0   // Version 6
            p[52] = UInt8(udpTotalLen >> 8)                   // Payload length
            p[53] = UInt8(udpTotalLen & 0xFF)
            p[54] = 17; p[55] = 64                            // Next Header: UDP, Hop Limit
            memcpy(p + 56, srcIP, 16)                         // Src = original sender
            memcpy(p + 72, dstIP, 16)                         // Dst = fake IP

            // --- First 8 bytes of original UDP ---
            p[88] = UInt8(srcPort >> 8); p[89] = UInt8(srcPort & 0xFF)
            p[90] = UInt8(dstPort >> 8); p[91] = UInt8(dstPort & 0xFF)
            p[92] = UInt8((udpTotalLen >> 8) & 0xFF)
            p[93] = UInt8(udpTotalLen & 0xFF)
            p[94] = 0; p[95] = 0                              // UDP checksum

            // ICMPv6 checksum (includes pseudo-header per RFC 4443 §2.3)
            var sum: UInt32 = 0
            // Pseudo-header: source address (outer src = dstIP)
            for i in stride(from: 8, to: 24, by: 2) {
                sum += UInt32(p[i]) << 8 | UInt32(p[i + 1])
            }
            // Pseudo-header: destination address (outer dst = srcIP)
            for i in stride(from: 24, to: 40, by: 2) {
                sum += UInt32(p[i]) << 8 | UInt32(p[i + 1])
            }
            // Pseudo-header: upper-layer packet length + next header (58)
            sum += UInt32(icmpLen)
            sum += 58
            // ICMPv6 header + data
            for i in stride(from: 40, to: packetLen, by: 2) {
                sum += UInt32(p[i]) << 8 | UInt32(p[i + 1])
            }
            while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16) }
            let cksum = ~UInt16(sum)
            p[42] = UInt8(cksum >> 8); p[43] = UInt8(cksum & 0xFF)
        }
        return packet
    }

    // MARK: - Output Batching

    /// Flushes accumulated output packets to the TUN device in a single writePackets call.
    /// Called via deferred lwipQueue.async after the current batch of lwip_bridge_input
    /// calls completes. Reduces kernel crossings from N to 1 per processing cycle.
    private func flushOutputPackets() {
        outputFlushScheduled = false
        guard !outputPackets.isEmpty else { return }
        let packets = outputPackets
        let protocols = outputProtocols
        outputPackets.removeAll(keepingCapacity: true)
        outputProtocols.removeAll(keepingCapacity: true)
        outputQueue.async { [weak self] in
            self?.packetFlow?.writePackets(packets, withProtocols: protocols)
        }
    }

    // MARK: - Packet Reading

    /// Continuously reads IP packets from the tunnel and feeds them into lwIP.
    private func startReadingPackets() {
        packetFlow?.readPackets { [weak self] packets, protocols in
            guard let self, self.running else { return }

            var uploadBytes: Int64 = 0
            for packet in packets {
                uploadBytes += Int64(packet.count)
            }

            self.lwipQueue.async {
                self.totalBytesOut += uploadBytes
                for i in 0..<packets.count {
                    packets[i].withUnsafeBytes { buffer in
                        guard let baseAddress = buffer.baseAddress else { return }
                        lwip_bridge_input(baseAddress, Int32(buffer.count))
                    }
                }
            }

            self.startReadingPackets()
        }
    }

    // MARK: - Timers

    /// Starts the lwIP periodic timeout timer (250ms interval).
    private func startTimeoutTimer() {
        let timer = DispatchSource.makeTimerSource(queue: lwipQueue)
        timer.schedule(deadline: .now() + .milliseconds(250),
                       repeating: .milliseconds(250))
        timer.setEventHandler { [weak self] in
            guard let self, self.running else { return }
            lwip_bridge_check_timeouts()
        }
        timer.resume()
        timeoutTimer = timer
    }

    /// Starts the UDP flow cleanup timer (1-second interval, 60-second idle timeout).
    private func startUDPCleanupTimer() {
        let timer = DispatchSource.makeTimerSource(queue: lwipQueue)
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
        timer.setEventHandler { [weak self] in
            guard let self, self.running else { return }
            let now = CFAbsoluteTimeGetCurrent()
            var keysToRemove: [UDPFlowKey] = []
            for (key, flow) in self.udpFlows {
                if now - flow.lastActivity > self.udpIdleTimeout {
                    flow.close()
                    keysToRemove.append(key)
                }
            }
            for key in keysToRemove {
                self.udpFlows.removeValue(forKey: key)
            }
        }
        timer.resume()
        udpCleanupTimer = timer
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
