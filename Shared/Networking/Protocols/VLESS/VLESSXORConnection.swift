//
//  VLESSXORConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/13/26.
//

import Foundation

/// Stream-XOR wrapper for VLESS encryption's `random` XOR mode. Per direction:
/// skip N bytes → XOR the 5-byte record header → skip the decoded body → repeat.
nonisolated final class VLESSXORConnection: ProxyConnection {
    private let inner: ProxyConnection

    private let outCTR: VLESSEncryptionCTR
    /// Nil until `installInboundCTR`: 0-RTT derives the inbound key from the first 16 server bytes.
    private var inCTR: VLESSEncryptionCTR?

    private var outSkip: Int
    private var inSkip: Int

    /// XOR'd header bytes accumulated across call boundaries; decoded at 5 bytes.
    private var outHeader = Data()
    private var inHeader = Data()

    /// Bytes past the inSkip region that arrived before `inCTR` was set; stashed
    /// verbatim and replayed through the state machine once it's installed.
    private var pendingPostSkip = Data()

    private let sendLock = UnfairLock()
    private let recvLock = UnfairLock()

    init(inner: ProxyConnection,
         outCTR: VLESSEncryptionCTR,
         inCTR: VLESSEncryptionCTR?,
         outSkip: Int,
         inSkip: Int) {
        self.inner = inner
        self.outCTR = outCTR
        self.inCTR = inCTR
        self.outSkip = outSkip
        self.inSkip = inSkip
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    /// Call once the 0-RTT path has derived the inbound key from the 16-byte server random.
    func installInboundCTR(_ ctr: VLESSEncryptionCTR) {
        recvLock.withLock { self.inCTR = ctr }
    }

    // MARK: Send

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        if data.isEmpty { completion(nil); return }
        var bytes = [UInt8](data)
        sendLock.withLock {
            applyOutboundMask(&bytes)
        }
        inner.sendRaw(data: Data(bytes), completion: completion)
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data, completion: { _ in })
    }

    /// XORs each TLS-record header in place, leaving sealed bodies and the skip region alone.
    private func applyOutboundMask(_ bytes: inout [UInt8]) {
        var offset = 0
        while offset < bytes.count {
            if outSkip > 0 {
                let consume = min(outSkip, bytes.count - offset)
                outSkip -= consume
                offset += consume
                continue
            }
            let needed = 5 - outHeader.count
            let avail = bytes.count - offset
            let chunk = min(needed, avail)
            bytes.withUnsafeMutableBufferPointer { ptr in
                let region = UnsafeMutableRawBufferPointer(
                    rebasing: UnsafeMutableRawBufferPointer(ptr)[offset..<(offset + chunk)]
                )
                outCTR.processInPlace(region)
            }
            outHeader.append(contentsOf: bytes[offset..<(offset + chunk)])
            offset += chunk
            if outHeader.count == 5 {
                let length = decodeHeaderLength(outHeader)
                outHeader.removeAll(keepingCapacity: true)
                outSkip = length
            } else {
                break
            }
        }
    }

    // MARK: Receive

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        // Drain stashed bytes first to preserve record-framing order.
        recvLock.lock()
        if !pendingPostSkip.isEmpty, inCTR != nil {
            var data = pendingPostSkip
            pendingPostSkip = Data()
            applyInboundMaskLocked(&data)
            recvLock.unlock()
            completion(data, nil)
            return
        }
        recvLock.unlock()

        inner.receiveRaw { [weak self] data, error in
            guard let self else {
                completion(nil, VLESSEncryptionError.connectionClosed)
                return
            }
            if let error { completion(nil, error); return }
            guard var data, !data.isEmpty else {
                completion(data, nil)
                return
            }
            self.recvLock.withLock {
                self.applyInboundMaskLocked(&data)
            }
            completion(data, nil)
        }
    }

    /// Inbound counterpart of `applyOutboundMask`. Caller must hold `recvLock`;
    /// while `inCTR` is nil, bytes past the skip region are stashed and truncated.
    private func applyInboundMaskLocked(_ data: inout Data) {
        guard data.count > 0 else { return }
        var bytes = [UInt8](data)
        var offset = 0
        while offset < bytes.count {
            if inSkip > 0 {
                let consume = min(inSkip, bytes.count - offset)
                inSkip -= consume
                offset += consume
                continue
            }
            guard let inCTR else {
                pendingPostSkip.append(contentsOf: bytes[offset..<bytes.count])
                bytes.removeSubrange(offset..<bytes.count)
                break
            }
            let needed = 5 - inHeader.count
            let avail = bytes.count - offset
            let chunk = min(needed, avail)
            bytes.withUnsafeMutableBufferPointer { ptr in
                let region = UnsafeMutableRawBufferPointer(
                    rebasing: UnsafeMutableRawBufferPointer(ptr)[offset..<(offset + chunk)]
                )
                inCTR.processInPlace(region)
            }
            inHeader.append(contentsOf: bytes[offset..<(offset + chunk)])
            offset += chunk
            if inHeader.count == 5 {
                let length = decodeHeaderLength(inHeader)
                inHeader.removeAll(keepingCapacity: true)
                inSkip = length
            } else {
                break
            }
        }
        data = Data(bytes)
    }

    // MARK: Cancel

    override func cancel() {
        inner.cancel()
    }

    // MARK: - Helpers

    /// Decodes bytes 3–4 of a TLS `application_data` header. Returns 0 on mismatch or
    /// out-of-range length so a corrupted stream re-enters header mode (matches Go).
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
