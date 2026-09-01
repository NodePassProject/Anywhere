//
//  TunnelStack+Callbacks.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "TunnelStack+Callbacks")

// MARK: - C-Callback Crossing Types

struct LWIPRawPointer: @unchecked Sendable { let raw: UnsafeRawPointer }

struct LWIPPCBHandle: @unchecked Sendable { let raw: UnsafeMutableRawPointer }

struct LWIPReleaseAction: @unchecked Sendable {
    let ctx: UnsafeMutableRawPointer?
    let fn: @convention(c) (UnsafeMutableRawPointer?) -> Void

    static let noop = LWIPReleaseAction(ctx: nil, fn: { _ in })

    func run() { fn(ctx) }
}

// MARK: - SYN-gate pressure sweep scratch

private struct PressureSweep {
    var now: TimeInterval = 0
    var establishing: Unmanaged<TCPConnection>?
    var establishingIdle: TimeInterval = -1
    var established: Unmanaged<TCPConnection>?
    var establishedIdle: TimeInterval = -1
}

nonisolated private let pressureSweepBox = Mutex(PressureSweep())

extension TunnelStack {

    // MARK: - Callback Installation

    func installLwipCallbacks() {
        lwip_bridge_set_host_ctx(BridgeContext.passUnretained(self))

        lwip_bridge_set_output_fn { data, len, isIPv6, releaseCtx, release in
            guard let stack = TunnelStack.lwipHost(), let data, let release else { return }
            let packet = Data(
                bytesNoCopy: UnsafeMutableRawPointer(mutating: data),
                count: Int(len),
                deallocator: .none
            )
            let releaseAction = LWIPReleaseAction(ctx: releaseCtx, fn: release)
            stack.assumeIsolated {
                $0.lwipDidOutput(packet, isIPv6: isIPv6 != 0, release: releaseAction)
            }
        }

        lwip_bridge_set_tcp_syn_filter_fn { _, _, dstIP, _, isIPv6 in
            guard let stack = TunnelStack.lwipHost() else {
                return Int32(LWIP_BRIDGE_SYN_PASS)
            }
            if let dstIP, stack.connectionRouter.isRejectMarkedDestination(rawIP: dstIP, isIPv6: isIPv6 != 0) {
                return Int32(LWIP_BRIDGE_SYN_DROP)
            }
            return stack.assumeIsolated { $0.lwipSynVerdict() }
        }

        lwip_bridge_set_tcp_stray_filter_fn { _, _, dstIP, _, isIPv6 in
            guard let stack = TunnelStack.lwipHost(), let dstIP,
                  stack.connectionRouter.isRejectMarkedDestination(rawIP: dstIP, isIPv6: isIPv6 != 0) else {
                return Int32(LWIP_BRIDGE_SYN_PASS)
            }
            return Int32(LWIP_BRIDGE_SYN_DROP)
        }

        lwip_bridge_set_tcp_accept_fn { _, _, dstIP, dstPort, isIPv6, pcb, silentDrop in
            guard let stack = TunnelStack.lwipHost(), let pcb, let dstIP else { return nil }
            let pcbHandle = LWIPPCBHandle(raw: pcb)
            let dstIPBox = LWIPRawPointer(raw: dstIP)
            let verdict = stack.assumeIsolated({
                $0.lwipAccept(pcb: pcbHandle.raw, dstIP: dstIPBox.raw, dstPort: dstPort, isIPv6: isIPv6 != 0)
            })
            switch verdict {
            case .accept(let connection):
                return connection.adopt()
            case .dropSilently:
                silentDrop?.pointee = 1
                return nil
            case .abort:
                return nil
            }
        }

        lwip_bridge_set_tcp_recv_fn { connection, data, len in
            guard let connection else {
                logger.debug("[LWIPBridge] tcp_recv: connection is nil")
                return
            }
            let dataBox = data.map { LWIPRawPointer(raw: $0) }
            BridgeContext.unretained(connection, as: TCPConnection.self).assumeIsolated { conn in
                if let dataBox, len > 0 {
                    conn.handleReceivedData(bytes: dataBox.raw, count: Int(len))
                } else {
                    conn.handleRemoteClose()
                }
            }
        }

        lwip_bridge_set_tcp_sent_fn { connection, len in
            guard let connection else { return }
            BridgeContext.unretained(connection, as: TCPConnection.self).assumeIsolated { $0.handleSent(len: len) }
        }

        lwip_bridge_set_tcp_err_fn { connection, err in
            guard let connection else {
                logger.debug("[LWIPBridge] tcp_err: connection is nil, err=\(err)")
                return
            }
            BridgeContext.consume(connection, as: TCPConnection.self).assumeIsolated { $0.handleError(err: err) }
        }
    }

    private static func lwipHost() -> TunnelStack? {
        guard let ctx = lwip_bridge_host_ctx() else { return nil }
        return BridgeContext.unretained(ctx, as: TunnelStack.self)
    }

    // MARK: - Callbacks

    func lwipDidOutput(_ packet: Data, isIPv6: Bool, release: LWIPReleaseAction) {
        let proto: NSNumber = isIPv6 ? Self.ipv6Proto : Self.ipv4Proto
        let needsKick: Bool = outputBuffer.withLock { buffer in
            buffer.packets.append(packet)
            buffer.protocols.append(proto)
            buffer.releases.append(release)
            if buffer.drainInFlight { return false }
            buffer.drainInFlight = true
            return true
        }
        if needsKick {
            kickOutputDrain()
        }
    }
    
    func lwipSynVerdict() -> Int32 {
        guard Int(lwip_bridge_active_tcp_count()) >= TunnelLimits.tcpMaxConnections else {
            return Int32(LWIP_BRIDGE_SYN_PASS)
        }
        let now = MonotonicClock.now
        guard let victim = findPressureVictim(now: now) else {
            tcpPressureLog.noteDropped(now: now, logger: logger)
            return Int32(LWIP_BRIDGE_SYN_DROP)
        }
        victim.connection.assumeIsolated { $0.evictForConnectionPressure(idleFor: victim.idleFor) }
        tcpPressureLog.noteEvicted(now: now, logger: logger)
        return Int32(LWIP_BRIDGE_SYN_PASS)
    }
    
    private func findPressureVictim(now: TimeInterval) -> (connection: TCPConnection, idleFor: TimeInterval)? {
        pressureSweepBox.withLock { $0 = PressureSweep(now: now) }
        lwip_bridge_for_each_tcp { arg in
            guard let arg else { return }
            let connection = BridgeContext.unretained(arg, as: TCPConnection.self)
            let now = pressureSweepBox.withLock { $0.now }
            guard let tier = connection.assumeIsolated({ $0.connectionPressureCandidate(now: now) }) else { return }
            pressureSweepBox.withLock { sweep in
                switch tier {
                case .establishing(let idleFor):
                    if idleFor > sweep.establishingIdle {
                        sweep.establishing = .passUnretained(connection)
                        sweep.establishingIdle = idleFor
                    }
                case .established(let idleFor):
                    if idleFor > sweep.establishedIdle {
                        sweep.established = .passUnretained(connection)
                        sweep.establishedIdle = idleFor
                    }
                }
            }
        }
        return pressureSweepBox.withLock { sweep in
            if let victim = sweep.establishing {
                return (victim.takeUnretainedValue(), sweep.establishingIdle)
            }
            if let victim = sweep.established {
                return (victim.takeUnretainedValue(), sweep.establishedIdle)
            }
            return nil
        }
    }

    enum AcceptVerdict {
        case accept(TCPConnection)
        case dropSilently
        case abort
    }

    func lwipAccept(
        pcb: UnsafeMutableRawPointer,
        dstIP: UnsafeRawPointer,
        dstPort: UInt16,
        isIPv6: Bool
    ) -> AcceptVerdict {
        guard let defaultConfiguration = configuration else {
            logger.debug("[TunnelStack] tcp_accept: guard failed")
            return .abort
        }

        let dstIPString = TunnelStack.ipAddrToString(dstIP, isIPv6: isIPv6)
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
            return .dropSilently
        case .unreachable:
            logger.debug("[TCP] Aborted (stale fake-IP): \(dstIPString):\(dstPort)")
            return .abort
        }

        let dstHost = decision.host

        var sniffSNI = !decision.hostIsResolvedDomain
        if mitmEnabled && mitmPolicy.matches(dstHost) {
            sniffSNI = true
        }

        return .accept(TCPConnection(
            stack: self,
            pcb: LWIPPCBHandle(raw: pcb),
            dstHost: dstHost,
            dstPort: dstPort,
            configuration: connectionConfiguration,
            routeTarget: routeTarget,
            ruleSetName: ruleSetName,
            sniffSNI: sniffSNI,
            hostIsResolvedDomain: decision.hostIsResolvedDomain,
            bridge: lwipBridge
        ))
    }
}
