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
    
    private var terminated = false
    
    var onFatalWrite: (@Sendable (AnywhereError) -> Void)?

    // MARK: Upload (app → upstream)

    private var uploadBuffer = Data()
    private var uploadWaiter: CheckedContinuation<Void, Never>?

    // MARK: Download (upstream → app)

    private var pendingWrite = Data()
    private var pendingWriteOffset = 0
    private var creditWaiter: CheckedContinuation<Void, Never>?
    private var downloadFinishing = false
    private var downloadFinished = false
    private var finishWaiter: CheckedContinuation<Void, Never>?
    private var writeError: AnywhereError?
    
    private let backlogBytesMirror = Atomic<Int>(0)
    
    private let downloadNeedsAwaitedSend = Atomic<Bool>(false)

    private var pendingWriteCount: Int { pendingWrite.count - pendingWriteOffset }
    
    init(bridge: LWIPConcurrencyBridge, pcb: LWIPPCBHandle) {
        self.bridge = bridge
        self.pcb = pcb.raw
    }

    // MARK: - Intake
    
    func deliverUpload(_ bytes: Data) {
        guard !terminated, !bytes.isEmpty else { return }
        uploadBuffer.append(bytes)
        resumeUploadWaiter()
    }
    
    func deliverSendCredit() {
        guard !terminated else { return }
        drainPendingWrite()
    }
    
    func terminate() {
        guard !terminated else { return }
        terminated = true
        downloadNeedsAwaitedSend.store(true, ordering: .relaxed)
        resumeUploadWaiter()
        resumeCreditWaiter()
        resumeFinishWaiter()
    }

    // MARK: - Establishment / teardown helpers
    
    func seedUpload(_ data: Data) {
        guard !terminated, !data.isEmpty else { return }
        uploadBuffer.append(data)
        resumeUploadWaiter()
    }
    
    func flushBestEffort() {
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
            if terminated { return nil }
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
    
    private func ackUpload(_ byteCount: Int) {
        guard !terminated, byteCount > 0 else { return }
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
        guard !terminated, !data.isEmpty else { return }
        backlogBytesMirror.wrappingAdd(data.count, ordering: .relaxed)
        pendingWrite.append(data)
        drainPendingWrite()
    }
    
    nonisolated var canPushDownload: Bool {
        !downloadNeedsAwaitedSend.load(ordering: .relaxed)
            && backlogBytesMirror.load(ordering: .relaxed) < TunnelConstants.drainLowWaterMark
    }
    
    nonisolated func pushDownload(_ data: Data) {
        backlogBytesMirror.wrappingAdd(data.count, ordering: .relaxed)
        bridge.enqueue { [self] in
            assumeIsolated { $0.acceptPushedDownload(data) }
        }
    }
    
    private func acceptPushedDownload(_ data: Data) {
        guard !terminated else {
            backlogBytesMirror.wrappingSubtract(data.count, ordering: .relaxed)
            return
        }
        pendingWrite.append(data)
        drainPendingWrite()
    }
    
    func sendDownload(_ data: Data) async throws {
        guard !terminated else { throw AnywhereError.transport(.terminated) }
        deliverDownload(data)
        while !terminated, writeError == nil, pendingWriteCount >= TunnelConstants.drainLowWaterMark {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                creditWaiter = continuation
            }
        }
        if let writeError { throw writeError }
        if terminated { throw AnywhereError.transport(.terminated) }
    }
    
    func awaitDownloadDrained() async {
        guard !terminated, writeError == nil else { return }
        downloadFinishing = true
        markDrainedIfComplete()
        while !terminated, writeError == nil, !downloadFinished {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                finishWaiter = continuation
            }
        }
    }
    
    private func drainPendingWrite() {
        guard !terminated, writeError == nil else { return }

        let live = pendingWriteCount
        if live > 0 {
            let written = pendingWrite.withUnsafeBytes { buffer -> Int in
                guard let base = buffer.baseAddress else { return 0 }
                return feedLWIP(base + pendingWriteOffset, count: live, retryOnEmpty: true)
            }
            if written < 0 {
                let error = AnywhereError.transport(.writeFailed(pending: live, sndbuf: Int(lwip_bridge_tcp_sndbuf(pcb))))
                writeError = error
                downloadNeedsAwaitedSend.store(true, ordering: .relaxed)
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
        guard downloadFinishing, !terminated, pendingWriteCount == 0 else { return }
        downloadFinishing = false
        downloadFinished = true
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
                if error == -1 { break }  // ERR_MEM: transient
                return -1                 // fatal
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
