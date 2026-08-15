//
//  TCPStreamConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/16/26.
//

import Foundation
import Synchronization

actor TCPStreamConcurrencyBridge {
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        bridge.executor.asUnownedSerialExecutor()
    }

    private let bridge: LWIPConcurrencyBridge
    private let pcb: UnsafeMutableRawPointer

    private enum Phase: PhaseTransitionable {
        case open
        case draining
        case drained
        case failed(AnywhereError)
        case terminated(writeError: AnywhereError?)

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.open, .draining),
                 (.draining, .drained),
                 (.drained, .open),
                 (.open, .failed),
                 (.draining, .failed),
                 (.drained, .failed):
                return true
            case (_, .terminated):
                return !old.isTerminated
            default:
                return false
            }
        }

        var isTerminated: Bool {
            if case .terminated = self { true } else { false }
        }

        var writeFailure: AnywhereError? {
            switch self {
            case .failed(let error), .terminated(.some(let error)): error
            default: nil
            }
        }
    }

    private var phase: Phase = .open

    var onFatalWrite: (@Sendable (AnywhereError) -> Void)?

    // MARK: Upload (app → upstream)

    private var uploadBuffer = Data()
    private var uploadWaiter: CheckedContinuation<Void, Never>?

    private var unreceivedBytes = 0

    // MARK: Download (upstream → app)

    private var pendingWrite = Data()
    private var pendingWriteOffset = 0
    private var creditWaiter: CheckedContinuation<Void, Never>?
    private var finishWaiter: CheckedContinuation<Void, Never>?

    private let backlogBytesMirror = Atomic<Int>(0)

    private let downloadNeedsAwaitedSend = OneShotLatch()

    private var pendingWriteCount: Int { pendingWrite.count - pendingWriteOffset }

    init(bridge: LWIPConcurrencyBridge, pcb: LWIPPCBHandle) {
        self.bridge = bridge
        self.pcb = pcb.raw
    }

    // MARK: - Intake

    func deliverUpload(_ bytes: Data) {
        guard !phase.isTerminated, !bytes.isEmpty else { return }
        uploadBuffer.append(bytes)
        unreceivedBytes += bytes.count
        resumeUploadWaiter()
    }

    func deliverSendCredit() {
        guard !phase.isTerminated else { return }
        drainPendingWrite()
    }

    func terminate() {
        let writeFailure = phase.writeFailure
        guard Phase.transition(&phase, to: .terminated(writeError: writeFailure)) else { return }
        downloadNeedsAwaitedSend.claim()
        resumeUploadWaiter()
        resumeCreditWaiter()
        resumeFinishWaiter()
    }

    // MARK: - Establishment / teardown helpers

    func seedUpload(_ data: Data) {
        guard !phase.isTerminated, !data.isEmpty else { return }
        uploadBuffer.append(data)
        unreceivedBytes += data.count
        resumeUploadWaiter()
    }

    func flushBestEffort() {
        guard !phase.isTerminated else { return }
        let live = pendingWriteCount
        guard live > 0 else { return }
        let written = pendingWrite.withUnsafeBytes { buffer -> Int in
            guard let base = buffer.baseAddress else { return 0 }
            return max(feedLWIP(base + pendingWriteOffset, count: live, retryOnEmpty: true), 0)
        }
        if written > 0 { lwip_bridge_tcp_output(pcb) }
    }

    // MARK: - Upload async surface

    func receiveUpload(acking ackedByteCount: Int) async -> Data? {
        ackUpload(ackedByteCount)
        while true {
            if phase.isTerminated { return nil }
            if !uploadBuffer.isEmpty {
                let chunk = uploadBuffer
                uploadBuffer = Data()
                return chunk
            }
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                uploadWaiter = continuation
            }
        }
    }

    func flushReceiveWindowForClose() {
        guard !phase.isTerminated, unreceivedBytes > 0 else { return }
        var remaining = unreceivedBytes
        unreceivedBytes = 0
        while remaining > 0 {
            let part = UInt16(min(remaining, Int(UInt16.max)))
            remaining -= Int(part)
            lwip_bridge_tcp_recved(pcb, part)
        }
    }

    private func ackUpload(_ byteCount: Int) {
        guard !phase.isTerminated, byteCount > 0 else { return }
        unreceivedBytes = max(0, unreceivedBytes - byteCount)
        var remaining = byteCount
        while remaining > 0 {
            let part = UInt16(min(remaining, Int(UInt16.max)))
            remaining -= Int(part)
            lwip_bridge_tcp_recved(pcb, part)
        }
        lwip_bridge_tcp_output(pcb)
    }

    // MARK: - Download async surface

    func deliverDownload(_ data: Data) {
        guard acceptDownload(data) else { return }
        drainPendingWrite()
    }

    private func acceptDownload(_ data: Data) -> Bool {
        guard !data.isEmpty else { return false }
        switch phase {
        case .terminated, .failed:
            return false
        case .drained:
            Phase.transition(&phase, to: .open)
        case .open, .draining:
            break
        }
        backlogBytesMirror.wrappingAdd(data.count, ordering: .relaxed)
        pendingWrite.append(data)
        return true
    }

    nonisolated var canPushDownload: Bool {
        !downloadNeedsAwaitedSend.isClaimed
            && backlogBytesMirror.load(ordering: .relaxed) < TunnelConstants.drainLowWaterMark
    }

    nonisolated func pushDownload(_ data: Data) {
        backlogBytesMirror.wrappingAdd(data.count, ordering: .relaxed)
        bridge.enqueue { [self] in
            assumeIsolated { $0.acceptPushedDownload(data) }
        }
    }

    private func acceptPushedDownload(_ data: Data) {
        switch phase {
        case .terminated, .failed:
            backlogBytesMirror.wrappingSubtract(data.count, ordering: .relaxed)
            return
        case .drained:
            Phase.transition(&phase, to: .open)
        case .open, .draining:
            break
        }
        pendingWrite.append(data)
        drainPendingWrite()
    }

    func sendDownload(_ data: Data) async throws {
        if let failure = phase.writeFailure { throw failure }
        guard !phase.isTerminated else { throw AnywhereError.transport(.terminated) }
        deliverDownload(data)
        while !phase.isTerminated, phase.writeFailure == nil,
              pendingWriteCount >= TunnelConstants.drainLowWaterMark {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                creditWaiter = continuation
            }
        }
        if let failure = phase.writeFailure { throw failure }
        if phase.isTerminated { throw AnywhereError.transport(.terminated) }
    }

    func awaitDownloadDrained() async {
        while true {
            switch phase {
            case .terminated, .failed, .drained:
                return
            case .open:
                Phase.transition(&phase, to: .draining)
                markDrainedIfComplete()
            case .draining:
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    finishWaiter = continuation
                }
            }
        }
    }

    private func drainPendingWrite() {
        switch phase {
        case .terminated, .failed: return
        case .open, .draining, .drained: break
        }

        let live = pendingWriteCount
        if live > 0 {
            let written = pendingWrite.withUnsafeBytes { buffer -> Int in
                guard let base = buffer.baseAddress else { return 0 }
                return feedLWIP(base + pendingWriteOffset, count: live, retryOnEmpty: true)
            }
            if written < 0 {
                let error = AnywhereError.transport(.writeFailed(pending: live, sndbuf: Int(lwip_bridge_tcp_sndbuf(pcb))))
                Phase.transition(&phase, to: .failed(error))
                downloadNeedsAwaitedSend.claim()
                resumeCreditWaiter()
                resumeFinishWaiter()
                onFatalWrite?(error)
                return
            }
            if written > 0 {
                backlogBytesMirror.wrappingSubtract(written, ordering: .relaxed)
                pendingWriteOffset += written
                if pendingWriteOffset >= pendingWrite.count {
                    pendingWrite.removeAll(keepingCapacity: true)
                    pendingWriteOffset = 0
                } else if pendingWriteOffset > pendingWrite.count - pendingWriteOffset {
                    pendingWrite.removeSubrange(0..<pendingWriteOffset)
                    pendingWriteOffset = 0
                }
                lwip_bridge_tcp_output(pcb)
            } else {
                scheduleDrainRetry()
                return
            }
        }

        markDrainedIfComplete()
        if pendingWriteCount < TunnelConstants.drainLowWaterMark {
            resumeCreditWaiter()
        }
    }

    private func markDrainedIfComplete() {
        guard case .draining = phase, pendingWriteCount == 0,
              Phase.transition(&phase, to: .drained) else { return }
        resumeFinishWaiter()
    }

    private func scheduleDrainRetry() {
        Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(TunnelConstants.drainRetryDelayMs))
            guard !Task.isCancelled else { return }
            await self?.drainPendingWrite()
        }
    }

    private func feedLWIP(_ base: UnsafeRawPointer, count: Int, retryOnEmpty: Bool) -> Int {
        var offset = 0
        while offset < count {
            var sndbuf = Int(lwip_bridge_tcp_sndbuf(pcb))
            if sndbuf <= 0 {
                if retryOnEmpty {
                    lwip_bridge_tcp_output(pcb)
                    sndbuf = Int(lwip_bridge_tcp_sndbuf(pcb))
                }
                guard sndbuf > 0 else { break }
            }
            let chunkSize = min(min(sndbuf, count - offset), TunnelConstants.tcpMaxWriteSize)
            let error = lwip_bridge_tcp_write(pcb, base + offset, UInt16(chunkSize))
            if error != 0 {
                if error == -1 { break }
                return -1
            }
            offset += chunkSize
        }
        return offset
    }

    // MARK: - Waiter resumption

    private func resumeUploadWaiter() {
        guard let waiter = uploadWaiter else { return }
        uploadWaiter = nil
        waiter.resume()
    }

    private func resumeCreditWaiter() {
        guard let waiter = creditWaiter else { return }
        creditWaiter = nil
        waiter.resume()
    }

    private func resumeFinishWaiter() {
        guard let waiter = finishWaiter else { return }
        finishWaiter = nil
        waiter.resume()
    }
}
