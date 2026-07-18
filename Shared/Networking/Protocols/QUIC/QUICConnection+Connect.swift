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
    
    nonisolated func connect() async throws {
        let resolvedIPs: [String] = transport == nil ? await DNSResolver.shared.resolveAll(host) : []
        try await bridge.runParkedThrowing(host: self) { me, continuation in
            guard me.state == .idle else {
                continuation.resume(throwing: QUICError.connectionFailed("Invalid state"))
                return
            }
            QUICCrypto.registerCallbacks()
            me.state = .connecting
            me.connectContinuation = continuation
            me.setupUDP(resolvedIPs: resolvedIPs)
        }
    }
    
    func finishConnect(_ error: Error?) {
        guard let continuation = connectContinuation else { return }
        connectContinuation = nil
        if let error { continuation.resume(throwing: error) } else { continuation.resume() }
    }
    
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

    func setupUDP(resolvedIPs: [String]) {
        if let transport {
            setupTunnelTransport(transport: transport)
        } else {
            setupDirectCarrier(resolvedIPs: resolvedIPs)
        }
    }

    func setupDirectCarrier(resolvedIPs: [String]) {
        do {
            populateRemoteAddr(resolvedIPs: resolvedIPs)
            guard remoteAddr.ss_family != 0 else {
                throw QUICError.connectionFailed("DNS lookup failed for \(host)")
            }
            let carrier = QUICDatagramCarrier(bridge: bridge, obfuscator: obfuscator)
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
            state = .closed
            closeCarrier()
            finishConnect(error)
        }
    }

    func setupTunnelTransport(transport: QUICDatagramTransport) {
        do {
            configurePlaceholderAddrs()
            try initializeNgtcp2()
            state = .handshaking
            if let obfuscator {
                startTransportSealPump(transport: transport, obfuscator: obfuscator)
            }
            startTransportReceiveLoop(transport: transport, localAddr: localAddr)
            writeToUDP()
            rescheduleTimer()
        } catch {
            state = .closed
            transport.cancel()
            finishConnect(error)
        }
    }
    
    func startTransportReceiveLoop(transport: QUICDatagramTransport, localAddr: sockaddr_storage) {
        let mailbox = QUICInboundMailbox()
        let obfuscator = self.obfuscator
        let bridge = self.bridge
        transportReceiveTask = Task.detached { [transport] in
            do {
                while true {
                    guard let data = try await transport.receiveDatagram() else {
                        bridge.enqueue { self.assumeIsolated { $0.handleTransportClosed(nil) } }
                        return
                    }
                    guard !data.isEmpty else { continue }
                    var packet = data
                    if let obfuscator {
                        guard let opened = obfuscator.open(data) else { continue }
                        packet = opened
                    }
                    if mailbox.push(packet) {
                        bridge.enqueue { self.assumeIsolated { $0.drainTransportInbound(mailbox, localAddr: localAddr) } }
                    }
                }
            } catch {
                bridge.enqueue { self.assumeIsolated { $0.handleTransportClosed(error) } }
            }
        }
    }
    
    func drainTransportInbound(_ mailbox: QUICInboundMailbox, localAddr: sockaddr_storage) {
        for packet in mailbox.take() {
            handleReceivedPacket(packet, localAddr: localAddr)
        }
    }
    
    func startTransportSealPump(transport: QUICDatagramTransport, obfuscator: QUICPacketObfuscator) {
        let (stream, continuation) = AsyncStream.makeStream(of: Data.self)
        transportSealContinuation = continuation
        transportSealTask = Task.detached { [transport] in
            for await raw in stream {
                let wireDatagrams = raw.withUnsafeBytes { obfuscator.seal($0) }
                for wire in wireDatagrams { transport.sendDatagram(wire) }
            }
        }
    }
    
    func handleTransportClosed(_ error: Error?) {
        let err = error ?? QUICError.closed
        finishConnect(err)
        close(error: err)
    }
    
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
        migratingCarrier?.assumeIsolated { $0.close() }
        clearMigrationState()
    }

    /// Fills `remoteAddr` from an IP-literal `host` or `resolvedIPs` (resolved off-queue by
    /// ``connect()`` — never resolve here: this runs on the serial bridge queue, where a
    /// blocking lookup would stall every connection sharing it).
    func populateRemoteAddr(resolvedIPs: [String]) {
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

        var found4: in_addr?
        var found6: in6_addr?
        for ip in resolvedIPs {
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
        parameters.disable_active_migration = migrationEnabled ? 0 : 1
        if datagramsEnabled {
            parameters.max_datagram_frame_size = Self.maxDatagramFrameSize
        }

        bridge.configureConnRef(&connRefStorage, host: self)
        
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
        
        bridge.setKeepAliveTimeout(connectionOpaquePointer, tuning.keepAliveTimeout)

        bridge.setTLSNativeHandle(
            connectionOpaquePointer,
            UnsafeMutableRawPointer(bitPattern: UInt(NGTCP2_APPLE_CS_AES_128_GCM_SHA256))
        )
        
        if case .brutal(let initialBps) = tuning.cc {
            let brutal = BrutalCongestionControl(initialBps: initialBps)
            if let ccKey = bridge.installBrutal(connectionOpaquePointer) {
                BrutalCongestionControl.register(brutal, for: ccKey)
                self.brutalCC = brutal
                self.brutalCCKey = ccKey
            }
        }
    }
    
    nonisolated func setBrutalBandwidth(_ bps: UInt64) {
        bridge.enqueue { [weak self] in
            self?.assumeIsolated { $0.brutalCC?.setTargetBandwidth(bps) }
        }
    }
    
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
