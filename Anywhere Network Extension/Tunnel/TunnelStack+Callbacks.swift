//
//  TunnelStack+Callbacks.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import Synchronization
import AnywhereIP

nonisolated private let logger = AnywhereLogger(category: "TunnelStack+Callbacks")

extension TunnelStack {
    func makeIPStack() -> IPStack {
        let generation = dataPlaneGeneration.wrappingAdd(1, ordering: .acquiringAndReleasing).newValue
        outputBuffer.withLock { $0.generation = generation }
        return IPStack(
            configuration: .init(
                maximumConnections: TunnelLimits.tcpMaxConnections,
                pendingSendBytes: TunnelConstants.tcpWindowSize,
                acknowledgmentDelay: TunnelConstants.tcpAcknowledgmentDelay
            ),
            output: { [weak self] packets in
                self?.enqueueTCPOutput(packets, generation: generation)
            },
            accept: { [weak self] pending in
                guard let self else { pending.reject(); return }
                Task { await self.accept(pending, generation: generation)?.start() }
            },
            datagrams: { [weak self] batch in
                self?.admitDatagrams(batch)
            },
            synFilter: { [weak self] _, destination in
                guard let self else { return .drop }
                guard !self.isRejectMarked(destination.address), self.ipStackSynVerdict() else {
                    self.recordRejectedSYN(to: destination)
                    return .drop
                }
                return .accept
            },
            strayFilter: { [weak self] _, destination in
                self.map { !$0.isRejectMarked(destination.address) } ?? false
            }
        )
    }

    nonisolated func isRejectMarked(_ address: IPAddress) -> Bool {
        withUnsafeTemporaryAllocation(byteCount: 16, alignment: 8) { bytes in
            address.write(to: bytes.baseAddress!)
            return connectionRouter.isRejectMarkedDestination(rawIP: bytes.baseAddress!, isIPv6: address.isIPv6)
        }
    }

    nonisolated private func recordRejectedSYN(to destination: IPEndpoint) {
        let ip = destination.address.description
        requestLog.record(
            protocol: .tcp,
            host: connectionRouter.fakeIPPool.lookup(ip: ip)?.domain ?? ip,
            port: destination.port,
            routeTarget: .reject
        )
    }

    nonisolated private func ipStackSynVerdict() -> Bool {
        guard tcpConnections.withLock({ $0.count }) >= TunnelLimits.tcpMaxConnections else { return true }
        let now = MonotonicClock.now
        guard let victim = findPressureVictim(now: now) else {
            tcpPressureLog.withLock { $0.noteDropped(now: now, logger: logger) }
            return false
        }
        victim.connection.evictForConnectionPressure(idleFor: victim.idleFor)
        tcpPressureLog.withLock { $0.noteEvicted(now: now, logger: logger) }
        return true
    }

    nonisolated private func findPressureVictim(now: TimeInterval) -> (connection: TCPConnection, idleFor: TimeInterval)? {
        var establishing: (connection: TCPConnection, idleFor: TimeInterval)?
        var established: (connection: TCPConnection, idleFor: TimeInterval)?
        for delegate in tcpConnections.withLock({ Array($0.connections.values) }) {
            guard let tier = delegate.connectionPressureCandidate(now: now) else { continue }
            switch tier {
            case .establishing(let idleFor):
                if idleFor > (establishing?.idleFor ?? -1) { establishing = (delegate, idleFor) }
            case .established(let idleFor):
                if idleFor > (established?.idleFor ?? -1) { established = (delegate, idleFor) }
            }
        }
        return establishing ?? established
    }

    private func accept(_ pending: PendingConnection, generation: UInt64) -> TCPConnection? {
        guard dataPlaneUp, dataPlaneGeneration.load(ordering: .acquiring) == generation, let defaultConfiguration = configuration else {
            logger.debug("[TunnelStack] tcp_accept: guard failed")
            pending.reject(); return nil
        }
        let dstIPString = pending.destination.address.description
        let dstPort = pending.destination.port
        let decision = connectionRouter.decision(forIP: dstIPString, port: dstPort, proto: "TCP")

        var connectionConfiguration = defaultConfiguration
        var routeTarget: RouteTarget = .default
        var ruleSetName: String? = nil

        switch decision.action {
        case .route(let target, let configuration, let matchedRuleSet):
            routeTarget = target
            ruleSetName = matchedRuleSet
            if let configuration {
                connectionConfiguration = configuration
            }
        case .reject(let matchedRuleSet):
            requestLog.record(
                protocol: .tcp,
                host: decision.host,
                port: dstPort,
                routeTarget: .reject,
                ruleSetName: matchedRuleSet
            )
            let reason = decision.hostIsResolvedDomain ? "fake-IP domain rule" : "IP rule"
            logger.debug("[TCP] Rejected by \(reason) (going dark): \(decision.host):\(dstPort)")
            pending.reject(reset: false); return nil
        case .unreachable:
            logger.debug("[TCP] Aborted (stale fake-IP): \(dstIPString):\(dstPort)")
            pending.reject(); return nil
        }

        let dstHost = decision.host

        var sniffSNI = !decision.hostIsResolvedDomain
        if mitmEnabled && mitmPolicy.matches(dstHost) {
            sniffSNI = true
        }
        
        guard let nativeConnection = pending.accept() else { return nil }
        let delegate = TCPConnection(
            stack: self,
            connection: nativeConnection,
            dstHost: dstHost,
            dstPort: dstPort,
            configuration: connectionConfiguration,
            routeTarget: routeTarget,
            ruleSetName: ruleSetName,
            sniffSNI: sniffSNI,
            hostIsResolvedDomain: decision.hostIsResolvedDomain
        )
        tcpConnections.withLock { $0.insert(delegate) }
        return delegate
    }
}
