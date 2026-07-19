//
//  VLESSXORConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/13/26.
//

import Foundation
import Synchronization

nonisolated final class VLESSXORConnection: ProxyConnection {
    private let inner: ProxyConnection

    private struct SendState {
        var outCTR: VLESSEncryptionCTR
        var outSkip: Int
        var outHeader = Data()
    }

    private struct ReceiveState {
        var inCTR: VLESSEncryptionCTR?
        var inSkip: Int
        var inHeader = Data()
        var pendingPostSkip = Data()
    }

    private let sendState: Mutex<SendState>
    private let receiveState: Mutex<ReceiveState>

    init(inner: ProxyConnection,
         outCTR: sending VLESSEncryptionCTR,
         inCTR: sending VLESSEncryptionCTR?,
         outSkip: Int,
         inSkip: Int) {
        self.inner = inner
        self.sendState = Mutex(SendState(outCTR: outCTR, outSkip: outSkip))
        self.receiveState = Mutex(ReceiveState(inCTR: inCTR, inSkip: inSkip))
    }

    var isConnected: Bool { inner.isConnected }
    var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    
    func installInboundCTR(key: Data, iv: Data) throws {
        try receiveState.withLock { $0.inCTR = try VLESSEncryptionCTR(key: key, iv: iv) }
    }

    // MARK: - Send

    func sendRaw(_ data: Data) async throws {
        if data.isEmpty { return }
        var bytes = [UInt8](data)
        sendState.withLock { state in
            applyOutboundMask(&bytes, state: &state)
        }
        try await inner.sendRaw(Data(bytes))
    }
    
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
            state.outCTR.processInPlace(&bytes, range: offset..<(offset + chunk))
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

    func receiveRaw() async throws -> Data? {
        let stashed: Data? = receiveState.withLock { state in
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
            return received
        }
        receiveState.withLock { state in
            applyInboundMask(&data, state: &state)
        }
        return data
    }
    
    private func applyInboundMask(_ data: inout Data, state: inout ReceiveState) {
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
            inCTR.processInPlace(&bytes, range: offset..<(offset + chunk))
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

    func cancel() {
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
