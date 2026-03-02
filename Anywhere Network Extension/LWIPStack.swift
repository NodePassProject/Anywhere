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
    private(set) var configuration: VLESSConfiguration?

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
    // routingRules     │ DomainRouter + FakeIPPool         │ Stack restart (closes connections
    //                  │                                   │ using outdated proxy configurations;
    //                  │                                   │ FakeIPPool rebuilt, not reset)

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

    /// Active UDP flows keyed by 5-tuple string (e.g. "10.0.0.1:1234-8.8.8.8:53").
    var udpFlows: [String: LWIPUDPFlow] = [:]
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
    /// All-integer comparison: UInt16 == UInt16, zero allocation per call.
    func shouldBypass(host: String) -> Bool {
        guard bypassCountry != 0 else { return false }
        return geoIPDatabase?.lookup(host) == bypassCountry
    }

    /// Reads the bypass country code from app group UserDefaults and converts to UInt16.
    private func loadBypassCountry() {
        let code = APCore.userDefaults.string(forKey: "bypassCountryCode") ?? ""
        bypassCountry = code.isEmpty ? 0 : GeoIPDatabase.packCountryCode(code)
        if bypassCountry != 0 {
            logger.info("[LWIPStack] Bypass country: \(code, privacy: .public)")
        }
    }

    /// Reads the DoH setting from app group UserDefaults.
    private func loadDoHSetting() {
        dohEnabled = APCore.userDefaults.bool(forKey: "dohEnabled")
    }

    // MARK: - Lifecycle

    /// Starts the lwIP stack and begins reading packets from the tunnel.
    ///
    /// - Parameters:
    ///   - packetFlow: The tunnel's packet flow for reading/writing IP packets.
    ///   - configuration: The VLESS proxy configuration.
    func start(packetFlow: NEPacketTunnelFlow,
               configuration: VLESSConfiguration,
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
            if configuration.muxEnabled && (configuration.flow == "xtls-rprx-vision" || configuration.flow == "xtls-rprx-vision-udp443") {
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
    func switchConfiguration(_ newConfiguration: VLESSConfiguration, ipv6Enabled: Bool? = nil) {
        logger.info("[LWIPStack] Switching configuration")
        lwipQueue.async { [self] in
            self.restartStack(configuration: newConfiguration,
                              ipv6Enabled: ipv6Enabled ?? self.ipv6Enabled)
        }
    }

    /// Shuts down the lwIP stack and all active flows. Must be called on `lwipQueue`.
    /// Note: Does NOT reset FakeIPPool. Callers handle pool lifecycle:
    /// - `stop()` calls `fakeIPPool.reset()` (full teardown, no reconnections expected).
    /// - `restartStack()` calls `fakeIPPool.rebuild()` (preserves mappings for cached DNS).
    private func shutdownInternal() {
        self.running = false
        self.totalBytesIn = 0
        self.totalBytesOut = 0

        self.timeoutTimer?.cancel()
        self.timeoutTimer = nil
        self.udpCleanupTimer?.cancel()
        self.udpCleanupTimer = nil

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
    /// Preserves FakeIPPool mappings across restart (rebuilt with updated configurations)
    /// so that apps holding cached fake IPs from before the restart still work.
    private func restartStack(configuration: VLESSConfiguration, ipv6Enabled: Bool) {
        shutdownInternal()

        self.configuration = configuration
        self.ipv6Enabled = ipv6Enabled
        self.running = true
        self.loadBypassCountry()
        self.loadDoHSetting()

        if configuration.muxEnabled && (configuration.flow == "xtls-rprx-vision" || configuration.flow == "xtls-rprx-vision-udp443") {
            self.muxManager = MuxManager(configuration: configuration, lwipQueue: self.lwipQueue)
        }

        self.domainRouter.loadRoutingConfiguration()
        self.fakeIPPool.rebuild(using: self.domainRouter)
        self.registerCallbacks()
        lwip_bridge_init()
        self.startTimeoutTimer()
        self.startUDPCleanupTimer()
        self.startReadingPackets()
        logger.info("[LWIPStack] Restarted, mux=\(self.muxManager != nil), bypass=\(self.bypassCountry != 0), doh=\(self.dohEnabled), ipv6=\(self.ipv6Enabled)")
    }

    // MARK: - Settings Observation
    //
    // Two Darwin notifications are observed. Both trigger a full stack restart
    // (shutdownInternal → restartStack), which closes all TCP/UDP connections,
    // clears the FakeIPPool, and re-reads settings. This ensures no stale
    // connections continue using outdated proxy configurations or routing rules.
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

            let newIPv6 = APCore.userDefaults.bool(forKey: "ipv6Enabled")
            let newBypassCode = APCore.userDefaults.string(forKey: "bypassCountryCode") ?? ""
            let newBypass = newBypassCode.isEmpty ? 0 : GeoIPDatabase.packCountryCode(newBypassCode)
            let newDoH = APCore.userDefaults.bool(forKey: "dohEnabled")

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
        // Output: lwIP → tunnel packet flow
        lwip_bridge_set_output_fn { data, len, isIPv6 in
            guard let shared = LWIPStack.shared, let data else { return }
            let byteCount = Int(len)
            let packetData = Data(bytes: data, count: byteCount)
            let proto = isIPv6 != 0 ? NSNumber(value: AF_INET6) : NSNumber(value: AF_INET)
            shared.totalBytesIn += Int64(byteCount)
            shared.outputQueue.async {
                shared.packetFlow?.writePackets([packetData], withProtocols: [proto])
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
                logger.debug("[LWIPStack] tcp_accept: dropping IPv6 connection (IPv6 disabled)")
                return nil
            }

            let dstIPString = LWIPStack.ipAddrToString(dstIP, isIPv6: isIPv6 != 0)

            var dstHost = dstIPString
            var connectionConfiguration = defaultConfiguration
            var forceBypass = false

            if FakeIPPool.isFakeIP(dstIPString) {
                if let entry = shared.fakeIPPool.lookup(ip: dstIPString) {
                    dstHost = entry.domain
                    forceBypass = entry.isDirect
                    connectionConfiguration = entry.configuration ?? defaultConfiguration
                } else {
                    // Fake IP but entry evicted from LRU — drop connection
                    logger.warning("[FakeIP] TCP to \(dstIPString, privacy: .public):\(dstPort) but no domain mapping found (evicted)")
                    return nil
                }
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
                logger.debug("[LWIPStack] udp_recv: dropping IPv6 packet (IPv6 disabled)")
                return
            }

            let payload = Data(bytes: data, count: Int(len))

            // DNS interception: intercept port-53 queries for matched domains
            if dstPort == 53 {
                if shared.handleDNSQuery(payload: payload,
                                          srcIP: srcIP, srcPort: srcPort,
                                          dstIP: dstIP, dstPort: dstPort,
                                          isIPv6: isIPv6 != 0) {
                    return  // Fake response sent, no flow needed
                }
                // No rule match — fall through, create normal UDP flow to proxy DNS
            }

            let srcHost = LWIPStack.ipAddrToString(srcIP, isIPv6: isIPv6 != 0)
            let dstIPString = LWIPStack.ipAddrToString(dstIP, isIPv6: isIPv6 != 0)

            // Fake-IP lookup for non-DNS packets
            var dstHost = dstIPString
            guard let defaultConfiguration = shared.configuration else { return }
            var flowConfiguration = defaultConfiguration
            var forceBypass = false

            if FakeIPPool.isFakeIP(dstIPString) {
                if let entry = shared.fakeIPPool.lookup(ip: dstIPString) {
                    dstHost = entry.domain
                    forceBypass = entry.isDirect
                    flowConfiguration = entry.configuration ?? defaultConfiguration
                } else {
                    // Fake IP but entry evicted from LRU — drop packet
                    logger.warning("[FakeIP] UDP to \(dstIPString, privacy: .public):\(dstPort) but no domain mapping found (evicted)")
                    return
                }
            }

            // flowKey uses dstIPString (not domain) for consistency with lwIP packet delivery
            let flowKey = "\(srcHost):\(srcPort)-\(dstIPString):\(dstPort)"

            if let flow = shared.udpFlows[flowKey] {
                flow.handleReceivedData(payload, payloadLength: Int(len))
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

    // MARK: - DNS Interception (Fake-IP)
    //
    // DNS queries arriving on UDP port 53 are checked here before creating any flow.
    // Two types of interception:
    //
    // 1. DDR blocking: When DoH is disabled, queries for "_dns.resolver.arpa" (RFC 9462)
    //    get a NODATA response. This prevents the system from discovering that the DNS
    //    server supports DoH and auto-upgrading, which would move all DNS to port 443
    //    and bypass our port-53 interception entirely.
    //
    // 2. Domain routing: A/AAAA queries for domains matching routing rules get a fake IP
    //    response from the FakeIPPool. When TCP/UDP connections later arrive at the fake IP,
    //    we look up the original domain and route through the assigned proxy.
    //
    // Unmatched queries fall through and create normal UDP flows to the DNS server via proxy.

    /// Intercepts a DNS query. Returns true if handled (no UDP flow needed).
    private func handleDNSQuery(payload: Data,
                                 srcIP: UnsafeRawPointer, srcPort: UInt16,
                                 dstIP: UnsafeRawPointer, dstPort: UInt16,
                                 isIPv6: Bool) -> Bool {
        // Parse domain + QTYPE
        var domainBuf = [CChar](repeating: 0, count: 256)
        var domainLen: Int = 255
        var qtype: UInt16 = 0

        let success = payload.withUnsafeBytes { ptr -> Int32 in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
            return parse_dns_query_ext(base, ptr.count, &domainBuf, &domainLen, &qtype)
        }
        guard success == 1 else { return false }

        let domain = String(cString: domainBuf).lowercased()

        // Block DDR (Discovery of Designated Resolvers, RFC 9462) when DoH is disabled
        // to prevent the system from auto-upgrading to DNS-over-HTTPS, which bypasses
        // port-53 interception needed for fake-IP domain routing.
        if !dohEnabled, domain == "_dns.resolver.arpa" {
            return sendNODATA(payload: payload, srcIP: srcIP, srcPort: srcPort,
                              dstIP: dstIP, dstPort: dstPort, isIPv6: isIPv6, qtype: qtype)
        }

        // Only intercept A (1) and AAAA (28) queries; let MX/SRV/etc. pass through
        guard qtype == 1 || qtype == 28 else { return false }

        // Skip if no routing rules loaded
        guard domainRouter.hasRules else { return false }

        // Check routing rules
        guard let action = domainRouter.matchDomain(domain) else {
            return false
        }

        let isDirect: Bool
        let configuration: VLESSConfiguration?
        switch action {
        case .direct:
            isDirect = true
            configuration = nil
        case .proxy(let id):
            isDirect = false
            configuration = domainRouter.resolveConfiguration(action: action)
            guard let configuration else {
                logger.warning("[FakeIP] Proxy configuration \(id) not found, forwarding DNS normally")
                return false
            }
        }

        // Allocate offset (same offset used for both A and AAAA of the same domain)
        let (offset, _) = fakeIPPool.allocate(domain: domain, configuration: configuration, isDirect: isDirect)

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
        var responseBuf = [UInt8](repeating: 0, count: 512)

        let responseLen = payload.withUnsafeBytes { queryPtr -> Int32 in
            guard let queryBase = queryPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
            if let fakeIPBytes {
                return fakeIPBytes.withUnsafeBufferPointer { ipPtr in
                    Int32(generate_dns_response(queryBase, queryPtr.count,
                                                ipPtr.baseAddress!, qtype,
                                                &responseBuf, responseBuf.count))
                }
            } else {
                return Int32(generate_dns_response(queryBase, queryPtr.count,
                                                   nil, qtype,
                                                   &responseBuf, responseBuf.count))
            }
        }

        guard responseLen > 0 else { return false }

        // Send response back via lwIP (swap src/dst so it goes back to the app)
        let responseData = Data(bytes: responseBuf, count: Int(responseLen))
        responseData.withUnsafeBytes { dataPtr in
            guard let dataBase = dataPtr.baseAddress else { return }
            lwip_bridge_udp_sendto(
                dstIP, dstPort,     // original dst becomes response src
                srcIP, srcPort,     // original src becomes response dst
                isIPv6 ? 1 : 0,
                dataBase, responseLen
            )
        }

        return true
    }

    /// Sends a NODATA DNS response (ANCOUNT=0) for the given query.
    private func sendNODATA(payload: Data,
                             srcIP: UnsafeRawPointer, srcPort: UInt16,
                             dstIP: UnsafeRawPointer, dstPort: UInt16,
                             isIPv6: Bool, qtype: UInt16) -> Bool {
        var responseBuf = [UInt8](repeating: 0, count: 512)
        let responseLen = payload.withUnsafeBytes { queryPtr -> Int32 in
            guard let queryBase = queryPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
            return Int32(generate_dns_response(queryBase, queryPtr.count,
                                                nil, qtype,
                                                &responseBuf, responseBuf.count))
        }
        guard responseLen > 0 else { return false }

        Data(bytes: responseBuf, count: Int(responseLen)).withUnsafeBytes { dataPtr in
            guard let dataBase = dataPtr.baseAddress else { return }
            lwip_bridge_udp_sendto(dstIP, dstPort, srcIP, srcPort,
                                    isIPv6 ? 1 : 0, dataBase, responseLen)
        }
        logger.info("[FakeIP] Blocked DDR query (qtype=\(qtype))")
        return true
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
            var keysToRemove: [String] = []
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
