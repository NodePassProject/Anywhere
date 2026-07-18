//
//  QUICConnection+Connect.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation
import Network
import CryptoKit
import Synchronization

extension QUICConnection {

    // MARK: Connect
    
    nonisolated func connect(completion: @escaping @Sendable (Error?) -> Void) {
        bridge.enqueue { [weak self] in
            guard let self else { completion(QUICError.connectionFailed("Invalid state")); return }
            self.assumeIsolated { me in
                guard me.state == .idle else {
                    completion(QUICError.connectionFailed("Invalid state"))
                    return
                }
                QUICCrypto.registerCallbacks()
                me.state = .connecting
                me.connectCompletion = completion
                me.setupUDP(completion: completion)
            }
        }
    }

    /// Async connect — the single-shot ngtcp2 connect completion is bridged in
    /// ``NGTCP2ConcurrencyBridge``.
    nonisolated func connect() async throws {
        try await bridge.awaitingCompletion { connect(completion: $0) }
    }

    /// RFC 8446 exporter for the completed QUIC TLS 1.3 connection.
    nonisolated func exportKeyingMaterial(label: String, context: Data, length: Int) async throws -> Data {
        let result: Result<Data, Error> = await bridge.run { [weak self] in
            guard let self else { return .failure(QUICError.closed) }
            return self.assumeIsolated { connection in
                guard connection.state == .connected, let tls = connection.tlsHandler else {
                    return .failure(QUICError.closed)
                }
                return Result { try tls.exportKeyingMaterial(label: label, context: context, length: length) }
            }
        }
        return try result.get()
    }


    // MARK: UDP

    func setupUDP(completion: @escaping @Sendable (Error?) -> Void) {
        if let transport {
            setupTunnelTransport(transport: transport, completion: completion)
        } else {
            setupDirectCarrier(completion: completion)
        }
    }

    func setupDirectCarrier(completion: @escaping @Sendable (Error?) -> Void) {
        do {
            populateRemoteAddr()
            guard remoteAddr.ss_family != 0 else {
                throw QUICError.connectionFailed("DNS lookup failed for \(host)")
            }
            let carrier = QUICDatagramCarrier(bridge: bridge)
            // The carrier shares this connection's executor (both on `bridge`), so its synchronous
            // surface is entered via `assumeIsolated` — we're already on the bridge queue. Our own
            // isolated addrs are copied through locals (the closure is the *carrier's* isolation).
            let remote = remoteAddr
            var local = localAddr
            try carrier.assumeIsolated { try $0.connect(remoteAddr: remote, localAddr: &local) }
            localAddr = local
            self.carrier = carrier
            try initializeNgtcp2()
            state = .handshaking
            armActiveCarrier(carrier, localAddr: localAddr)
            writeToUDP()
            rescheduleTimer()
        } catch {
            // Nil connectCompletion before firing to prevent double-fire from stray callbacks.
            state = .closed
            closeCarrier()
            connectCompletion = nil
            completion(error)
        }
    }

    /// Wires ngtcp2 to a datagram transport (chained QUIC). Placeholder addrs are safe:
    /// chained QUIC rides a fixed relay path and never migrates; the transport routes.
    func setupTunnelTransport(
        transport: QUICDatagramTransport,
        completion: @escaping @Sendable (Error?) -> Void
    ) {
        do {
            configurePlaceholderAddrs()
            try initializeNgtcp2()
            state = .handshaking
            startTransportReceiveLoop(transport: transport, localAddr: localAddr)
            writeToUDP()
            rescheduleTimer()
        } catch {
            state = .closed
            transport.cancel()
            connectCompletion = nil
            completion(error)
        }
    }

    /// Owns the pull loop feeding inbound datagrams from a chained `QUICDatagramTransport` into
    /// ngtcp2. The task is actor-isolated (strong self), so each `receiveDatagram()` resumes back on
    /// the bridge queue and the packet is fed synchronously here. It captures `transport` strongly —
    /// the resource it drives — so the strong-self loop owns the connection while receiving.
    /// `performTeardown` cancels the task and `transport.cancel()` unblocks the parked pull, ending
    /// the loop so ARC reclaims both (breaking the connection → task → self cycle).
    func startTransportReceiveLoop(transport: QUICDatagramTransport, localAddr: sockaddr_storage) {
        transportReceiveTask = Task { [transport] in
            do {
                while true {
                    guard let data = try await transport.receiveDatagram() else {
                        self.handleTransportClosed(nil)   // clean EOF: the relay closed
                        return
                    }
                    self.handleReceivedPacket(data, localAddr: localAddr)
                }
            } catch {
                self.handleTransportClosed(error)
            }
        }
    }

    /// Terminal outcome of the chained-transport receive loop: fires any pending connect completion,
    /// then closes. Isolated (the loop resumes on the bridge queue).
    func handleTransportClosed(_ error: Error?) {
        let err = error ?? QUICError.closed
        if let callback = connectCompletion {
            connectCompletion = nil
            callback(err)
        }
        close(error: err)
    }

    /// Stable placeholder addrs for ngtcp2's path identity check; never used for routing.
    func configurePlaceholderAddrs() {
        addrLen = MemoryLayout<sockaddr_in>.size
        withUnsafeMutablePointer(to: &remoteAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                sin.pointee = sockaddr_in()
                sin.pointee.sin_len = UInt8(addrLen)
                sin.pointee.sin_family = sa_family_t(AF_INET)
                sin.pointee.sin_port = port.bigEndian
                sin.pointee.sin_addr.s_addr = UInt32(0x7f000001).bigEndian  // 127.0.0.1
            }
        }
        withUnsafeMutablePointer(to: &localAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                sin.pointee = sockaddr_in()
                sin.pointee.sin_len = UInt8(addrLen)
                sin.pointee.sin_family = sa_family_t(AF_INET)
                sin.pointee.sin_addr.s_addr = INADDR_ANY
            }
        }
    }

    func closeCarrier() {
        carrier?.assumeIsolated { $0.close() }
        carrier = nil
        // Also retire any in-flight migration target, so closing mid-migration doesn't
        // leak its NWConnection or leave a deferred path_validation/deadline on stale state.
        migratingCarrier?.assumeIsolated { $0.close() }
        clearMigrationState()
    }

    func populateRemoteAddr() {
        var addr4 = in_addr()
        if inet_pton(AF_INET, host, &addr4) == 1 {
            configureIPv4(addr4)
            return
        }

        var addr6 = in6_addr()
        if inet_pton(AF_INET6, host, &addr6) == 1 {
            configureIPv6(addr6)
            return
        }

        // Cache-backed resolver — a direct getaddrinfo() would block the queue.
        var found4: in_addr?
        var found6: in6_addr?
        for ip in DNSResolver.shared.resolveAll(host) {
            if found4 == nil {
                var a4 = in_addr()
                if inet_pton(AF_INET, ip, &a4) == 1 {
                    found4 = a4
                    continue
                }
            }
            if found6 == nil {
                var a6 = in6_addr()
                if inet_pton(AF_INET6, ip, &a6) == 1 {
                    found6 = a6
                }
            }
        }

        if let a4 = found4 {
            configureIPv4(a4)
        } else if let a6 = found6 {
            configureIPv6(a6)
        }
    }

    func configureIPv4(_ addr: in_addr) {
        addrLen = MemoryLayout<sockaddr_in>.size
        withUnsafeMutablePointer(to: &remoteAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                sin.pointee = sockaddr_in()
                sin.pointee.sin_len = UInt8(addrLen)
                sin.pointee.sin_family = sa_family_t(AF_INET)
                sin.pointee.sin_port = port.bigEndian
                sin.pointee.sin_addr = addr
            }
        }
        withUnsafeMutablePointer(to: &localAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                sin.pointee = sockaddr_in()
                sin.pointee.sin_len = UInt8(addrLen)
                sin.pointee.sin_family = sa_family_t(AF_INET)
                sin.pointee.sin_addr.s_addr = INADDR_ANY
            }
        }
    }

    func configureIPv6(_ addr: in6_addr) {
        addrLen = MemoryLayout<sockaddr_in6>.size
        withUnsafeMutablePointer(to: &remoteAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                sin6.pointee = sockaddr_in6()
                sin6.pointee.sin6_len = UInt8(addrLen)
                sin6.pointee.sin6_family = sa_family_t(AF_INET6)
                sin6.pointee.sin6_port = port.bigEndian
                sin6.pointee.sin6_addr = addr
            }
        }
        withUnsafeMutablePointer(to: &localAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                sin6.pointee = sockaddr_in6()
                sin6.pointee.sin6_len = UInt8(addrLen)
                sin6.pointee.sin6_family = sa_family_t(AF_INET6)
                sin6.pointee.sin6_addr = in6addr_any
            }
        }
    }


    // MARK: ngtcp2 Init

    func initializeNgtcp2() throws {
        generateConnectionID(&dcid, length: 16)
        generateConnectionID(&scid, length: 16)

        tlsHandler = QUICTLSHandler(serverName: serverName, alpn: alpn)

        var callbacks = bridge.makeCallbacks(datagramsEnabled: datagramsEnabled)

        var settings = bridge.defaultSettings()
        settings.initial_ts = currentTimestamp()
        // Chained transports use the RFC 9000 §14 floor; see chainedMaxUDPPayload.
        settings.max_tx_udp_payload_size = (transport != nil) ? Self.chainedMaxUDPPayload : Self.maxUDPPayload
        settings.cc_algo = tuning.ngtcp2CCAlgo
        settings.max_stream_window = tuning.maxStreamWindow
        settings.max_window = tuning.maxWindow
        settings.handshake_timeout = tuning.handshakeTimeout
        var parameters = bridge.defaultTransportParams()
        parameters.initial_max_streams_bidi = tuning.initialMaxStreamsBidi
        parameters.initial_max_streams_uni = tuning.initialMaxStreamsUni
        parameters.initial_max_data = tuning.initialMaxData
        parameters.initial_max_stream_data_bidi_local = tuning.initialMaxStreamDataBidiLocal
        parameters.initial_max_stream_data_bidi_remote = tuning.initialMaxStreamDataBidiRemote
        parameters.initial_max_stream_data_uni = tuning.initialMaxStreamDataUni
        parameters.max_idle_timeout = tuning.maxIdleTimeout
        // Advertise migration support only when we can migrate (direct carrier); chained
        // QUIC honestly declares it won't. ngtcp2 gates *our* migration on the server's
        // flag, not this one — this is just the correct outbound declaration.
        parameters.disable_active_migration = migrationEnabled ? 0 : 1
        if datagramsEnabled {
            parameters.max_datagram_frame_size = Self.maxDatagramFrameSize
        }

        bridge.configureConnRef(&connRefStorage, host: self)

        // PMTUD only over the direct carrier: chained probes don't reflect the
        // wire MTU, and a probe failure trips blackhole detection on a routine inner drop.
        let usePMTUD = (transport == nil)
        let (conn, rv) = bridge.createClientConn(
            dcid: &dcid, scid: &scid,
            localAddr: &localAddr, remoteAddr: &remoteAddr, addrLen: addrLen,
            version: UInt32(NGTCP2_PROTO_VER_V1),
            callbacks: &callbacks, settings: &settings,
            pmtudProbes: usePMTUD ? Self.pmtudProbes : nil,
            params: &parameters, connRef: &connRefStorage
        )
        guard rv == 0, let connectionOpaquePointer = conn else {
            throw QUICError.connectionFailed("ngtcp2_conn_client_new: \(rv)")
        }
        self.connectionOpaquePointer = connectionOpaquePointer

        // Keep-alive PINGs detect silently-broken UDP paths (NAT rebind, idle sweep).
        bridge.setKeepAliveTimeout(connectionOpaquePointer, tuning.keepAliveTimeout)

        bridge.setTLSNativeHandle(connectionOpaquePointer,
            UnsafeMutableRawPointer(bitPattern: UInt(NGTCP2_APPLE_CS_AES_128_GCM_SHA256)))

        // Install Brutal after conn_client_new and before any packets, so no
        // stale CUBIC decisions leak through.
        if case .brutal(let initialBps) = tuning.cc {
            let brutal = BrutalCongestionControl(initialBps: initialBps)
            if let ccKey = bridge.installBrutal(connectionOpaquePointer) {
                BrutalCongestionControl.register(brutal, for: ccKey)
                self.brutalCC = brutal
                self.brutalCCKey = ccKey
            }
        }
    }

    /// Updates the Brutal target send rate (bytes/sec); no-op if Brutal isn't installed. Safe off-queue.
    nonisolated func setBrutalBandwidth(_ bps: UInt64) {
        bridge.enqueue { [weak self] in
            self?.assumeIsolated { $0.brutalCC?.setTargetBandwidth(bps) }
        }
    }

    /// Reverts to CUBIC (`Hysteria-CC-RX: auto`); safe off-queue. Unregisters BEFORE rewiring
    /// the CC table so a racing trampoline no-ops rather than touching a half-initialized CUBIC struct.
    nonisolated func uninstallBrutalCC() {
        bridge.enqueue { [weak self] in
            self?.assumeIsolated { me in
                guard let connectionOpaquePointer = me.connectionOpaquePointer else { return }
                if let key = me.brutalCCKey {
                    BrutalCongestionControl.unregister(cc: key)
                    me.brutalCCKey = nil
                    me.brutalCC = nil
                }
                me.bridge.uninstallBrutal(connectionOpaquePointer)
            }
        }
    }

}
