//
//  VLESSXORConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/13/26.
//

import Foundation

/// Stream-XOR connection wrapper used by VLESS encryption's `random` XOR
/// mode (XorMode == 2).
///
/// State machine for each direction:
/// - Skip the next `skip` bytes (no XOR). For the outbound side this
///   covers the 0-RTT pre-write blob; for inbound it covers the server's
///   pre-record padding bytes still in flight when the wrapper takes over.
/// - XOR exactly 5 bytes (the record header). Decode the embedded length
///   to know how many bytes of body to skip next.
/// - Loop back to skip mode for the body length, then header again.
nonisolated final class VLESSXORConnection: ProxyConnection {
    private let inner: ProxyConnection

    /// CTR keystream applied to outbound bytes.
    private let outCTR: VLESSEncryptionCTR
    /// CTR keystream applied to inbound bytes. Optional because 0-RTT
    /// derives the peer key from the first 16 server bytes — it's set
    /// lazily by ``installInboundCTR(_:)`` before any inbound XOR happens.
    private var inCTR: VLESSEncryptionCTR?

    /// Bytes remaining in the current "skip" run before the next 5-byte
    /// header should be XOR'd. Mutates on each call.
    private var outSkip: Int
    private var inSkip: Int

    /// Partial header bytes accumulated across receive boundaries. The
    /// Go code uses a 5-byte stack buffer plus a separate length cursor;
    /// in Swift it's simpler to keep the XOR'd-so-far bytes in a small
    /// Data and decode the length once it reaches 5.
    private var outHeader = Data()
    private var inHeader = Data()

    /// Bytes that arrived past the leading inSkip region while `inCTR`
    /// was still nil (0-RTT setup hadn't yet derived the server random).
    /// Held verbatim and replayed through the XOR state machine as soon
    /// as ``installInboundCTR(_:)`` lands. Without this stash the bytes
    /// would either be returned unmasked (the protocol then mis-decodes
    /// the next record header) or trigger a precondition.
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

    /// Wire up the inbound CTR once the 0-RTT path has read the 16-byte
    /// server random and derived the AEAD key from it.
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

    /// Walk `bytes` and XOR each TLS-record header in place while leaving
    /// the AEAD-sealed bodies (and any leading skip-region) alone.
    private func applyOutboundMask(_ bytes: inout [UInt8]) {
        var offset = 0
        while offset < bytes.count {
            // Phase 1: drop into "skip" until we exhaust the current run.
            if outSkip > 0 {
                let consume = min(outSkip, bytes.count - offset)
                outSkip -= consume
                offset += consume
                continue
            }
            // Phase 2: XOR up to 5 bytes (a record header). May span calls.
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
                // Header still incomplete — wait for the next chunk.
                break
            }
        }
    }

    // MARK: Receive

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        // Drain any stashed post-skip bytes (held while inCTR was nil)
        // before pulling more from the inner conn — otherwise they'd be
        // re-ordered after fresh bytes and break record framing.
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

    /// Walk `data` and XOR each TLS-record header in place. Called with
    /// the recv lock held. If `inCTR` isn't set yet (0-RTT before the
    /// server random has been read), any bytes past the leading `inSkip`
    /// region are stashed in ``pendingPostSkip`` and truncated out of the
    /// returned buffer — the caller will see only the unmasked skip-region
    /// bytes, and the stashed remainder gets replayed once
    /// ``installInboundCTR(_:)`` lands.
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
                // 0-RTT, pre-CTR-install: stash everything past offset
                // and truncate the returned buffer. The state machine
                // resumes once the CTR lands.
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

    /// Big-endian decode of bytes 3-4 of an `application_data` record.
    /// Falls back to 0 if the prefix doesn't match — same forgiving
    /// behavior as Go's `DecodeHeader` so a corrupted or pre-padding byte
    /// stream produces 0 skip and re-enters header mode on the next chunk.
    private func decodeHeaderLength(_ header: Data) -> Int {
        precondition(header.count == 5)
        let base = header.startIndex
        if header[base] != 23 || header[base + 1] != 3 || header[base + 2] != 3 {
            return 0
        }
        let length = (Int(header[base + 3]) << 8) | Int(header[base + 4])
        if length < 17 || length > 16640 { return 0 }
        return length
    }
}
