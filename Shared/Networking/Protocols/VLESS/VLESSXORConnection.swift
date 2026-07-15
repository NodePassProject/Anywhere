//
//  VLESSXORConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/13/26.
//

import Foundation
import Synchronization

/// Stream-XOR wrapper for VLESS encryption's `random` XOR mode. Per direction:
/// skip N bytes → XOR the 5-byte record header → skip the decoded body → repeat.
nonisolated final class VLESSXORConnection: ProxyConnection {
    private let inner: ProxyConnection

    private let outCTR: VLESSEncryptionCTR

    private struct SendState {
        var outSkip: Int
        /// XOR'd header bytes accumulated across call boundaries; decoded at 5 bytes.
        var outHeader = Data()
    }

    private struct RecvState {
        /// Nil until `installInboundCTR`: 0-RTT derives the inbound key from the first 16 server bytes.
        var inCTR: VLESSEncryptionCTR?
        var inSkip: Int
        /// XOR'd header bytes accumulated across call boundaries; decoded at 5 bytes.
        var inHeader = Data()
        /// Bytes past the inSkip region that arrived before `inCTR` was set; stashed
        /// verbatim and replayed through the state machine once it's installed.
        var pendingPostSkip = Data()
    }

    private let sendState: Mutex<SendState>
    private let recvState: Mutex<RecvState>

    init(inner: ProxyConnection,
         outCTR: VLESSEncryptionCTR,
         inCTR: VLESSEncryptionCTR?,
         outSkip: Int,
         inSkip: Int) {
        self.inner = inner
        self.outCTR = outCTR
        self.sendState = Mutex(SendState(outSkip: outSkip))
        self.recvState = Mutex(RecvState(inCTR: inCTR, inSkip: inSkip))
        super.init()
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    /// Call once the 0-RTT path has derived the inbound key from the 16-byte server random.
    func installInboundCTR(_ ctr: VLESSEncryptionCTR) {
        recvState.withLock { $0.inCTR = ctr }
    }

    // MARK: - Send

    override func sendRaw(_ data: Data) async throws {
        if data.isEmpty { return }
        var bytes = [UInt8](data)
        sendState.withLock { state in
            applyOutboundMask(&bytes, state: &state)
        }
        try await inner.sendRaw(Data(bytes))
    }

    /// XORs each TLS-record header in place, leaving sealed bodies and the skip region alone.
    /// Call inside `sendState.withLock`.
    private func applyOutboundMask(_ bytes: inout [UInt8], state: inout SendState) {
        var offset = 0
        while offset < bytes.count {
            if state.outSkip > 0 {
                let consume = min(state.outSkip, bytes.count - offset)
                state.outSkip -= consume
                offset += consume
                continue
            }
            let needed = 5 - state.outHeader.count
            let avail = bytes.count - offset
            let chunk = min(needed, avail)
            bytes.withUnsafeMutableBufferPointer { pointer in
                let region = UnsafeMutableRawBufferPointer(
                    rebasing: UnsafeMutableRawBufferPointer(pointer)[offset..<(offset + chunk)]
                )
                outCTR.processInPlace(region)
            }
            state.outHeader.append(contentsOf: bytes[offset..<(offset + chunk)])
            offset += chunk
            if state.outHeader.count == 5 {
                let length = decodeHeaderLength(state.outHeader)
                state.outHeader.removeAll(keepingCapacity: true)
                state.outSkip = length
            } else {
                break
            }
        }
    }

    // MARK: - Receive

    override func receiveRaw() async throws -> Data? {
        // Drain stashed bytes first to preserve record-framing order.
        let stashed: Data? = recvState.withLock { state in
            guard !state.pendingPostSkip.isEmpty, state.inCTR != nil else { return nil }
            var data = state.pendingPostSkip
            state.pendingPostSkip = Data()
            applyInboundMask(&data, state: &state)
            return data
        }
        if let stashed {
            return stashed
        }

        let received = try await inner.receiveRaw()
        guard var data = received, !data.isEmpty else {
            // EOF (nil) or an empty chunk passes through unchanged.
            return received
        }
        recvState.withLock { state in
            applyInboundMask(&data, state: &state)
        }
        return data
    }

    /// Inbound counterpart of `applyOutboundMask`. Call inside `recvState.withLock`;
    /// while `inCTR` is nil, bytes past the skip region are stashed and truncated.
    private func applyInboundMask(_ data: inout Data, state: inout RecvState) {
        guard data.count > 0 else { return }
        var bytes = [UInt8](data)
        var offset = 0
        while offset < bytes.count {
            if state.inSkip > 0 {
                let consume = min(state.inSkip, bytes.count - offset)
                state.inSkip -= consume
                offset += consume
                continue
            }
            guard let inCTR = state.inCTR else {
                state.pendingPostSkip.append(contentsOf: bytes[offset..<bytes.count])
                bytes.removeSubrange(offset..<bytes.count)
                break
            }
            let needed = 5 - state.inHeader.count
            let avail = bytes.count - offset
            let chunk = min(needed, avail)
            bytes.withUnsafeMutableBufferPointer { pointer in
                let region = UnsafeMutableRawBufferPointer(
                    rebasing: UnsafeMutableRawBufferPointer(pointer)[offset..<(offset + chunk)]
                )
                inCTR.processInPlace(region)
            }
            state.inHeader.append(contentsOf: bytes[offset..<(offset + chunk)])
            offset += chunk
            if state.inHeader.count == 5 {
                let length = decodeHeaderLength(state.inHeader)
                state.inHeader.removeAll(keepingCapacity: true)
                state.inSkip = length
            } else {
                break
            }
        }
        data = Data(bytes)
    }

    // MARK: - Cancel

    override func cancel() {
        inner.cancel()
    }

    // MARK: - Helpers

    /// Decodes bytes 3–4 of a TLS `application_data` header. Returns 0 on mismatch or
    /// out-of-range length so a corrupted stream re-enters header mode.
    private func decodeHeaderLength(_ header: Data) -> Int {
        let base = header.startIndex
        if header[base] != 23 || header[base + 1] != 3 || header[base + 2] != 3 {
            return 0
        }
        let length = (Int(header[base + 3]) << 8) | Int(header[base + 4])
        if length < 17 || length > 16640 { return 0 }
        return length
    }
}
