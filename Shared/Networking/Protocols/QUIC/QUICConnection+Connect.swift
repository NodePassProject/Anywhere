//
//  QUICConnection+Connect.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation
import Synchronization
import Network
import AnywhereQUIC

private struct WeakConnectionBox: Sendable {
    weak var value: QUICConnection?
}

extension QUICConnection {

    // MARK: Connect

    nonisolated func connect() async throws {
        let dialAttempt = ConnectionMetrics.currentAttempt
        let resolvedIPs: [String] = transport == nil ? await DNSResolver.shared.resolveAll(host) : []
        try await bridge.runParkedThrowing(host: self) { me, continuation in
            guard me.phase == .idle else {
                continuation.resume(throwing: AnywhereError.quic(.connectionFailed(detail: "Invalid state")))
                return
            }
            me.transition(to: .connecting)
            me.dialAttempt = dialAttempt
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
            guard let self else { return .failure(AnywhereError.quic(.closed(graceful: false))) }
            return self.assumeIsolated { connection in
                guard connection.phase == .connected, let tls = connection.tlsHandler else {
                    return .failure(AnywhereError.quic(.closed(graceful: false)))
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
                throw AnywhereError.quic(.connectionFailed(detail: "DNS lookup failed for \(host)"))
            }
            let carrier = QUICDatagramCarrier(bridge: bridge, obfuscator: obfuscator)
            let remote = remoteAddr
            var local = localAddr
            try carrier.assumeIsolated { try $0.connect(remoteAddr: remote, localAddr: &local) }
            localAddr = local
            self.carrier = carrier
            try initializeQUIC()
            transition(to: .handshaking)
            armActiveCarrier(carrier, localAddr: localAddr)
            writeToUDP()
            rescheduleTimer()
        } catch {
            performTeardown(error: error)
        }
    }

    func setupTunnelTransport(transport: QUICDatagramTransport) {
        do {
            configurePlaceholderAddrs()
            try initializeQUIC()
            transition(to: .handshaking)
            startTransportIO(transport: transport)
            writeToUDP()
            rescheduleTimer()
        } catch {
            performTeardown(error: error)
        }
    }

    func startTransportIO(transport: QUICDatagramTransport) {
        let localAddr = self.localAddr
        let bridge = self.bridge
        let obfuscator = self.obfuscator

        var sealStream: AsyncStream<Data>?
        if obfuscator != nil {
            let (stream, continuation) = AsyncStream.makeStream(
                of: Data.self,
                bufferingPolicy: .bufferingOldest(Self.maxQueuedTransportDatagrams)
            )
            transportSealContinuation = continuation
            sealStream = stream
        }

        let host = WeakConnectionBox(value: self)
        rootTask = Task {
            await Self.runTransportDriver(
                host: host, bridge: bridge, transport: transport, obfuscator: obfuscator,
                sealStream: sealStream, localAddr: localAddr
            )
        }
    }

    @concurrent
    private static func runTransportDriver(
        host: WeakConnectionBox,
        bridge: QUICConcurrencyBridge,
        transport: QUICDatagramTransport,
        obfuscator: QUICPacketObfuscator?,
        sealStream: AsyncStream<Data>?,
        localAddr: sockaddr_storage
    ) async {
        await withDiscardingTaskGroup { group in
            group.addTask {
                await Self.runTransportReceiveLoop(
                    host: host,
                    bridge: bridge,
                    transport: transport,
                    obfuscator: obfuscator,
                    localAddr: localAddr
                )
            }
            if let sealStream, let obfuscator {
                group.addTask {
                    await Self.runTransportSealPump(transport: transport, stream: sealStream, obfuscator: obfuscator)
                }
            }
        }
    }

    private static func runTransportReceiveLoop(
        host: WeakConnectionBox,
        bridge: QUICConcurrencyBridge,
        transport: QUICDatagramTransport,
        obfuscator: QUICPacketObfuscator?,
        localAddr: sockaddr_storage
    ) async {
        do {
            while true {
                guard let data = try await transport.receiveDatagram() else {
                    bridge.enqueue { host.value?.assumeIsolated { $0.handleTransportClosed(nil) } }
                    return
                }
                guard !data.isEmpty else { continue }
                var packet = data
                if let obfuscator {
                    guard let opened = obfuscator.open(data) else { continue }
                    packet = opened
                }
                let datagram = packet
                bridge.enqueue { host.value?.assumeIsolated { $0.handleReceivedPacket(datagram, localAddr: localAddr) } }
            }
        } catch {
            bridge.enqueue { host.value?.assumeIsolated { $0.handleTransportClosed(error) } }
        }
    }

    private static func runTransportSealPump(
        transport: QUICDatagramTransport, stream: AsyncStream<Data>, obfuscator: QUICPacketObfuscator
    ) async {
        for await raw in stream {
            let wireDatagrams = raw.withUnsafeBytes { obfuscator.seal($0) }
            for wire in wireDatagrams { transport.sendDatagram(wire) }
        }
    }

    func handleTransportClosed(_ error: Error?) {
        let err = error ?? AnywhereError.quic(.closed(graceful: false))
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
        if case .proactiveProbing(let target, _) = migration {
            target.assumeIsolated { $0.close() }
        } else if case .proactiveValidating(let target, _) = migration {
            target.assumeIsolated { $0.close() }
        }
        setMigration(.none)
    }

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


    // MARK: QUIC engine

    func initializeQUIC() throws {
        let tls = QUICTLSHandler(serverName: serverName, alpn: alpn)
        tlsHandler = tls
        let payloadSize = transport != nil ? Self.chainedMaxUDPPayload : directMaxUDPPayload
        var probes = Self.pmtudProbes.filter { $0 <= payloadSize }
        if let maximumProbe = UInt16(exactly: payloadSize),
           maximumProbe > UInt16(Self.chainedMaxUDPPayload),
           !probes.contains(maximumProbe) {
            probes.append(maximumProbe)
        }
        let settings = QUICSettings(
            maxSendUDPPayloadSize: payloadSize,
            handshakeTimeout: .nanoseconds(Int64(tuning.handshakeTimeout)),
            maxStreamWindow: tuning.maxStreamWindow,
            maxConnectionWindow: tuning.maxWindow,
            pmtudProbes: probes,
            isPMTUDEnabled: transport == nil,
            keepAliveTimeout: .nanoseconds(Int64(tuning.keepAliveTimeout)),
            localConnectionIDLength: 16,
            maxPendingDatagrams: Self.maxPendingDatagrams
        )
        let parameters = QUICTransportParameters(
            maxIdleTimeout: .nanoseconds(Int64(tuning.maxIdleTimeout)),
            initialMaxData: tuning.initialMaxData,
            initialMaxStreamDataBidirectionalLocal: tuning.initialMaxStreamDataBidiLocal,
            initialMaxStreamDataBidirectionalRemote: tuning.initialMaxStreamDataBidiRemote,
            initialMaxStreamDataUnidirectional: tuning.initialMaxStreamDataUni,
            initialMaxStreamsBidirectional: tuning.initialMaxStreamsBidi,
            initialMaxStreamsUnidirectional: tuning.initialMaxStreamsUni,
            isActiveMigrationDisabled: !migrationEnabled,
            maxDatagramFrameSize: datagramsEnabled ? Self.maxDatagramFrameSize : 0
        )
        let controller = tuning.makeCongestionController()
        brutalCC = controller as? QUICBrutalCongestionController
        let engine = AnywhereQUIC.QUICConnection(
            settings: settings,
            transportParameters: parameters,
            destinationID: .random(length: 16),
            path: quicPath(local: localAddr),
            tls: tls,
            congestionController: controller,
            now: currentTimestamp()
        )
        self.engine = engine
        txBuffer = [UInt8](repeating: 0, count: engine.settings.maxSendUDPPayloadSize)
    }

    nonisolated func setBrutalBandwidth(_ bps: UInt64) {
        bridge.enqueue { [weak self] in
            self?.assumeIsolated { $0.brutalCC?.bytesPerSecond = bps }
        }
    }

    nonisolated func uninstallBrutalCC() {
        bridge.enqueue { [weak self] in
            self?.assumeIsolated { me in
                guard let engine = me.engine, me.brutalCC != nil else { return }
                me.brutalCC = nil
                engine.setCongestionController(QUICCubicCongestionController(), now: me.currentTimestamp())
                me.scheduleFlush()
            }
        }
    }
}
