//
//  PacketFlowBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 9/27/26.
//

import Foundation
import Synchronization
@preconcurrency import NetworkExtension
import AnywhereIP

nonisolated final class PacketFlowWriter: @unchecked Sendable {
    private typealias WritePackets = @convention(c) (NSObject, Selector, NSArray, NSArray) -> ObjCBool

    private static let selector = NSSelectorFromString("writePackets:withProtocols:")
    private static let ipv4 = NSNumber(value: AF_INET)
    private static let ipv6 = NSNumber(value: AF_INET6)

    private let flow: NEPacketTunnelFlow
    private let writePackets: WritePackets?

    init(_ flow: NEPacketTunnelFlow) {
        self.flow = flow
        writePackets = flow.responds(to: Self.selector) ? unsafeBitCast(flow.method(for: Self.selector), to: WritePackets.self) : nil
    }

    func write(_ packets: ArraySlice<OutboundPacket>) -> Bool {
        var objects: [NSData] = []
        var protocols: [NSNumber] = []
        objects.reserveCapacity(packets.count)
        protocols.reserveCapacity(packets.count)
        for packet in packets {
            objects.append(packet.data)
            protocols.append(packet.isIPv6 ? Self.ipv6 : Self.ipv4)
        }
        if let writePackets {
            return writePackets(flow, Self.selector, objects as NSArray, protocols as NSArray).boolValue
        }
        return flow.writePackets(objects.map { Data(referencing: $0) }, withProtocols: protocols)
    }
}

nonisolated final class InboundBatch: @unchecked Sendable {
    private let storage: NSArray
    let packets: [UnsafeRawBufferPointer]
    let byteCount: Int

    init(_ storage: NSArray) {
        self.storage = storage
        let array = storage as CFArray
        let count = CFArrayGetCount(array)
        var packets: [UnsafeRawBufferPointer] = []
        packets.reserveCapacity(count)
        var byteCount = 0
        for index in 0..<count {
            let packet = Unmanaged<CFData>.fromOpaque(CFArrayGetValueAtIndex(array, index)).takeUnretainedValue()
            let length = CFDataGetLength(packet)
            packets.append(UnsafeRawBufferPointer(start: CFDataGetBytePtr(packet), count: length))
            byteCount += length
        }
        self.packets = packets
        self.byteCount = byteCount
    }
}

nonisolated final class InboundQueue: Sendable {
    private struct State {
        var pending: [InboundBatch] = []
        var pendingBytes = 0
        var paused = false
        var finished = false
        var waiter: CheckedContinuation<Void, Never>?
    }

    private let state = Mutex(State())
    private let limit: Int

    init(limit: Int) {
        self.limit = limit
    }

    func push(_ batch: InboundBatch) -> Bool {
        let (waiter, keepReading): (CheckedContinuation<Void, Never>?, Bool) = state.withLock { s in
            guard !s.finished else { return (nil, false) }
            s.pending.append(batch)
            s.pendingBytes += batch.byteCount
            let waiter = s.waiter
            s.waiter = nil
            guard s.pendingBytes < limit else {
                s.paused = true
                return (waiter, false)
            }
            return (waiter, true)
        }
        waiter?.resume()
        return keepReading
    }

    func next() async -> [InboundBatch]? {
        while true {
            let batches: [InboundBatch]? = state.withLock { s in
                guard !s.pending.isEmpty else { return nil }
                let batches = s.pending
                s.pending.removeAll(keepingCapacity: true)
                return batches
            }
            if let batches { return batches }
            guard await park() else { return nil }
        }
    }

    func didConsume(_ batches: [InboundBatch]) -> Bool {
        var bytes = 0
        for batch in batches { bytes += batch.byteCount }
        return state.withLock { s in
            s.pendingBytes -= bytes
            guard s.paused, !s.finished, s.pendingBytes <= limit / 2 else { return false }
            s.paused = false
            return true
        }
    }

    func finish() {
        let waiter: CheckedContinuation<Void, Never>? = state.withLock { s in
            s.finished = true
            s.pending.removeAll()
            s.pendingBytes = 0
            defer { s.waiter = nil }
            return s.waiter
        }
        waiter?.resume()
    }

    private func park() async -> Bool {
        await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let ready: Bool = state.withLock { s in
                    if !s.pending.isEmpty || s.finished || Task.isCancelled { return true }
                    s.waiter = continuation
                    return false
                }
                if ready { continuation.resume() }
            }
        } onCancel: {
            let waiter: CheckedContinuation<Void, Never>? = state.withLock { s in
                defer { s.waiter = nil }
                return s.waiter
            }
            waiter?.resume()
        }
        return !Task.isCancelled && state.withLock { !$0.finished }
    }
}

nonisolated final class PacketReader: @unchecked Sendable {
    private typealias ReadPackets = @convention(c) (NSObject, Selector, @escaping @convention(block) (NSArray?, NSArray?) -> Void) -> Void

    private static let selector = NSSelectorFromString("readPacketsWithCompletionHandler:")

    private let flow: NEPacketTunnelFlow
    private let readPackets: ReadPackets?
    private let deliver: @Sendable (InboundBatch) -> Bool
    private let stopped = Atomic<Bool>(false)
    private let waiter = Mutex<CheckedContinuation<Void, Never>?>(nil)

    init(flow: NEPacketTunnelFlow, deliver: @escaping @Sendable (InboundBatch) -> Bool) {
        self.flow = flow
        self.deliver = deliver
        readPackets = flow.responds(to: Self.selector) ? unsafeBitCast(flow.method(for: Self.selector), to: ReadPackets.self) : nil
    }

    func run() async {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                waiter.withLock { $0 = continuation }
                if stopped.load(ordering: .acquiring) {
                    stop()
                } else {
                    arm()
                }
            }
        } onCancel: {
            stop()
        }
    }

    func resume() {
        guard !stopped.load(ordering: .acquiring) else { return }
        arm()
    }

    private func stop() {
        stopped.store(true, ordering: .releasing)
        waiter.withLock { waiter in
            defer { waiter = nil }
            return waiter
        }?.resume()
    }

    private func arm() {
        if let readPackets {
            readPackets(flow, Self.selector) { [self] packets, _ in receive(packets) }
        } else {
            flow.readPackets { [self] packets, _ in receive(packets.map { $0 as NSData } as NSArray) }
        }
    }

    private func receive(_ packets: NSArray?) {
        guard !stopped.load(ordering: .acquiring) else { return }
        if let packets, packets.count > 0, !deliver(InboundBatch(packets)) { return }
        guard !stopped.load(ordering: .acquiring) else { return }
        arm()
    }
}
