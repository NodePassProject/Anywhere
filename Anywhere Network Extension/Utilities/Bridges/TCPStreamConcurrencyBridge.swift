//
//  TCPStreamConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/16/26.
//

import Foundation

actor TCPStreamConcurrencyBridge {

    nonisolated var unownedExecutor: UnownedSerialExecutor {
        bridge.executor.asUnownedSerialExecutor()
    }

    enum StreamError: Error {
        /// The relay was torn down (teardown/cancel) while an I/O call was in flight.
        case terminated
        /// `tcp_write` returned a fatal (non-`ERR_MEM`) error; the connection must abort.
        case writeFailed(pending: Int, sndbuf: Int)
    }

    private let bridge: LWIPConcurrencyBridge
    private let pcb: UnsafeMutableRawPointer

    /// Torn down: intake is dropped and in-flight I/O calls unwind. Set by ``terminate()``.
    private var terminated = false

    // MARK: Upload (app → upstream)
    //
    // Coalesces a synchronous burst of lwIP recv callbacks so the relay ships one large send;
    // `tcp_recved` is deferred until the upstream accepts a chunk (the ack rides the next
    // ``receiveUpload(acking:)``), so TCP_WND caps how far ahead the buffer runs.

    private var uploadBuffer = Data()
    private var uploadBufferOffset = 0
    private var uploadEOF = false
    private var uploadWaiter: CheckedContinuation<Void, Never>?

    private var uploadCount: Int { uploadBuffer.count - uploadBufferOffset }

    // MARK: Download (upstream → app)
    //
    // `[0, pendingWriteOffset)` is already handed to lwIP; compaction is deferred until the dead
    // prefix outgrows the live suffix. `sendDownload` parks on `creditWaiter` while the backlog
    // is at/above the low-water mark, so the upstream peer is throttled to what the app drains.

    private var pendingWrite = Data()
    private var pendingWriteOffset = 0
    private var creditWaiter: CheckedContinuation<Void, Never>?
    private var downloadFinishing = false
    private var downloadFinished = false
    private var finishWaiter: CheckedContinuation<Void, Never>?
    private var writeError: StreamError?

    private var pendingWriteCount: Int { pendingWrite.count - pendingWriteOffset }
    
    init(bridge: LWIPConcurrencyBridge, pcb: LWIPPCBHandle) {
        self.bridge = bridge
        self.pcb = pcb.raw
    }

    // MARK: - Intake (lwIP queue; entered via the owner's `assumeIsolated`)

    /// New upload bytes from the local app (lwIP `tcp_recv`). Copies eagerly — `ptr` is valid
    /// only for this call.
    func deliverUpload(_ bytes: Data) {
        guard !terminated, !bytes.isEmpty else { return }
        uploadBuffer.append(bytes)
        resumeUploadWaiter()
    }

    /// The app half-closed its send direction (lwIP `tcp_recv` with an empty pbuf).
    func deliverUploadEOF() {
        guard !terminated else { return }
        uploadEOF = true
        resumeUploadWaiter()
    }

    /// The client ACK freed lwIP send-buffer space (lwIP `tcp_sent`): drain more backlog.
    func deliverSendCredit() {
        guard !terminated else { return }
        drainPendingWrite()
    }

    /// Stops both relay loops (teardown/cancel). The owner still drives the pcb close/abort.
    func terminate() {
        guard !terminated else { return }
        terminated = true
        resumeUploadWaiter()
        resumeCreditWaiter()
        resumeFinishWaiter()
    }

    // MARK: - Establishment / teardown helpers

    /// Seeds bytes buffered during sniff/dial (the app's pre-connect payload) ahead of the relay.
    func seedUpload(_ data: Data) {
        guard !terminated, !data.isEmpty else { return }
        uploadBuffer.append(data)
        resumeUploadWaiter()
    }

    /// Best-effort flush of the download backlog before the owner closes the pcb, so drained
    /// bytes precede the FIN. Fatal errors are ignored (the close supersedes them).
    func flushBestEffort() {
        let live = pendingWriteCount
        guard live > 0 else { return }
        let written = pendingWrite.withUnsafeBytes { buffer -> Int in
            guard let base = buffer.baseAddress else { return 0 }
            return max(feedLWIP(base + pendingWriteOffset, count: live, retryOnEmpty: true), 0)
        }
        if written > 0 { bridge.tcpOutput(pcb) }
    }

    // MARK: - Upload async surface (single upload relay)

    /// The next coalesced upload chunk (≤ `uploadChunkSize`), or `nil` once the app's FIN is
    /// reached and the buffer is drained. Acks `acking` bytes — the previously delivered chunk,
    /// now accepted by the upstream — in the same hop (ack-on-take), so each relay cycle crosses
    /// the lwIP queue once; the final chunk's ack rides the call that returns `nil`. Termination
    /// wins over buffered data — a torn-down connection's residue must not reach the upstream,
    /// the relay must exit promptly, and the ack is skipped so it never touches the freed pcb.
    func receiveUpload(acking ackedByteCount: Int) async -> Data? {
        ackUpload(ackedByteCount)
        while true {
            if terminated { return nil }
            if uploadCount > 0 {
                return sliceUpload(min(uploadCount, TunnelConstants.uploadChunkSize))
            }
            if uploadEOF { return nil }
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                uploadWaiter = continuation
            }
        }
    }

    /// Acks `byteCount` upload bytes back to lwIP once the upstream accepted them, reopening the
    /// receive window. Deferred until acceptance so the app is throttled to the upstream's rate.
    /// Rides ``receiveUpload(acking:)``'s hop rather than a hop of its own.
    private func ackUpload(_ byteCount: Int) {
        guard !terminated, byteCount > 0 else { return }
        var remaining = byteCount
        while remaining > 0 {
            let part = UInt16(min(remaining, Int(UInt16.max)))
            remaining -= Int(part)
            bridge.tcpRecved(pcb, part)
        }
        bridge.tcpOutput(pcb)
    }

    /// Removes and returns the `take`-byte head slice; whole-buffer consumption hands off the
    /// storage so the in-flight chunk's backing isn't mutated under it.
    private func sliceUpload(_ take: Int) -> Data {
        if take == uploadCount {
            let chunk: Data = uploadBufferOffset == 0
                ? uploadBuffer
                : uploadBuffer.subdata(in: uploadBufferOffset..<uploadBuffer.count)
            uploadBuffer = Data()
            uploadBufferOffset = 0
            return chunk
        }
        let start = uploadBufferOffset
        let end = start + take
        let chunk = uploadBuffer.subdata(in: start..<end)
        uploadBufferOffset = end
        if uploadBufferOffset > uploadBuffer.count - uploadBufferOffset {
            uploadBuffer.removeSubrange(0..<uploadBufferOffset)
            uploadBufferOffset = 0
        }
        return chunk
    }

    // MARK: - Download async surface (single download relay)

    /// Fire-and-forget push (MITM inner-leg output): appends `data` and drains, with no
    /// backpressure. Ordering is preserved by the single lwIP-queue caller.
    func deliverDownload(_ data: Data) {
        guard !terminated, !data.isEmpty else { return }
        pendingWrite.append(data)
        drainPendingWrite()
    }

    /// Hands `data` to lwIP for the local app, parking until the backlog drains below the
    /// low-water mark so the upstream is throttled. Throws ``StreamError`` on teardown or a
    /// fatal `tcp_write`.
    func sendDownload(_ data: Data) async throws {
        guard !terminated else { throw StreamError.terminated }
        deliverDownload(data)
        while !terminated, writeError == nil, pendingWriteCount >= TunnelConstants.drainLowWaterMark {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                creditWaiter = continuation
            }
        }
        if let writeError { throw writeError }
        if terminated { throw StreamError.terminated }
    }

    /// The upstream EOF'd: wait until the download backlog has fully drained into lwIP so the
    /// full close doesn't truncate the tail. No FIN is sent (half-close removed) — the owner
    /// full-closes once both directions have ended.
    func awaitDownloadDrained() async {
        guard !terminated else { return }
        downloadFinishing = true
        markDrainedIfComplete()
        while !terminated, !downloadFinished {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                finishWaiter = continuation
            }
        }
    }

    /// Drains `pendingWrite` into lwIP; on no progress (`ERR_MEM`/zero window) schedules a retry,
    /// on a fatal error latches ``writeError``. Resumes the download relay once capacity opens.
    private func drainPendingWrite() {
        guard !terminated, writeError == nil else { return }

        let live = pendingWriteCount
        if live > 0 {
            let written = pendingWrite.withUnsafeBytes { buffer -> Int in
                guard let base = buffer.baseAddress else { return 0 }
                return feedLWIP(base + pendingWriteOffset, count: live, retryOnEmpty: true)
            }
            if written < 0 {
                writeError = .writeFailed(pending: live, sndbuf: bridge.tcpSendBuffer(pcb))
                resumeCreditWaiter()
                return
            }
            if written > 0 {
                pendingWriteOffset += written
                if pendingWriteOffset >= pendingWrite.count {
                    pendingWrite.removeAll(keepingCapacity: true)
                    pendingWriteOffset = 0
                } else if pendingWriteOffset > pendingWrite.count - pendingWriteOffset {
                    pendingWrite.removeSubrange(0..<pendingWriteOffset)
                    pendingWriteOffset = 0
                }
                bridge.tcpOutput(pcb)
            } else {
                // Nothing drained (ERR_MEM / zero window): retry after a delay.
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

    /// Ports `TCPConnection.feedLWIP`: writes up to `count` bytes, returning bytes written,
    /// `0` on no progress (`ERR_MEM`/zero window), or `-1` on a fatal error.
    private func feedLWIP(_ base: UnsafeRawPointer, count: Int, retryOnEmpty: Bool) -> Int {
        var offset = 0
        while offset < count {
            var sndbuf = bridge.tcpSendBuffer(pcb)
            if sndbuf <= 0 {
                if retryOnEmpty {
                    bridge.tcpOutput(pcb)
                    sndbuf = bridge.tcpSendBuffer(pcb)
                }
                guard sndbuf > 0 else { break }
            }
            let chunkSize = min(min(sndbuf, count - offset), TunnelConstants.tcpMaxWriteSize)
            let error = bridge.tcpWrite(pcb, base + offset, UInt16(chunkSize))
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
