//
//  HysteriaObfuscator.swift
//  Anywhere
//
//  Created by NodePassProject on 6/23/26.
//

import Foundation
import Security

// MARK: - Salamander

/// XOR obfuscation: every datagram is `salt(8) || (packet XOR keystream)`, where the keystream is
/// BLAKE2b-256 over `password || salt` cycled to the packet length.
final class SalamanderObfuscator: QUICPacketObfuscator {
    static let saltLength = 8
    private static let keyLength = 32  // BLAKE2b-256 digest

    private let passwordBytes: [UInt8]

    init(password: String) {
        self.passwordBytes = Array(password.utf8)
    }

    private func keystream(salt: [UInt8]) -> [UInt8] {
        BLAKE2bHasher.hash256(passwordBytes, salt)
    }

    func seal(_ packet: UnsafeRawBufferPointer) -> [Data] {
        var salt = [UInt8](repeating: 0, count: Self.saltLength)
        _ = SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt)
        let key = keystream(salt: salt)

        var out = [UInt8]()
        out.reserveCapacity(Self.saltLength + packet.count)
        out.append(contentsOf: salt)
        for index in 0..<packet.count {
            out.append(packet[index] ^ key[index % Self.keyLength])
        }
        return [Data(out)]
    }

    func open(_ datagram: Data) -> Data? {
        let count = datagram.count
        // Too short to carry a salt; pass through untouched.
        guard count > Self.saltLength else { return datagram }
        return datagram.withUnsafeBytes { raw -> Data in
            let source = raw.bindMemory(to: UInt8.self)
            let salt = Array(UnsafeBufferPointer(start: source.baseAddress, count: Self.saltLength))
            let key = keystream(salt: salt)
            var out = [UInt8](repeating: 0, count: count - Self.saltLength)
            for index in 0..<out.count {
                out[index] = source[Self.saltLength + index] ^ key[index % Self.keyLength]
            }
            return Data(out)
        }
    }
}

// MARK: - Gecko

/// Wraps Salamander, additionally fragmenting long-header (handshake) packets into 2–8 randomly
/// padded chunks reassembled by `msgID`. 1-RTT (short-header) packets pass through with Salamander
/// only.
///
/// All methods run on `QUICConnection.queue`, so reassembly state needs no locking.
final class GeckoObfuscator: QUICPacketObfuscator {
    private static let fragmentFlag: UInt8 = 0x80
    private static let headerLength = 5
    private static let minChunks = 2
    private static let maxChunks = 8
    private static let reassemblyTTLNanos: UInt64 = 8 * 1_000_000_000
    private static let sweepIntervalNanos: UInt64 = 4 * 1_000_000_000
    private static let maxReassembly = 64

    private let inner: SalamanderObfuscator
    private let minPacketSize: Int
    private let maxPacketSize: Int
    private var msgIDCounter: UInt8 = 0

    private final class Reassembly {
        var chunks: [[UInt8]?]
        var received = 0
        let total: Int
        let deadline: UInt64
        init(total: Int, deadline: UInt64) {
            self.chunks = Array(repeating: nil, count: total)
            self.total = total
            self.deadline = deadline
        }
    }

    /// Keyed by `msgID`.
    private var reassembly: [UInt8: Reassembly] = [:]
    private var lastSweep: UInt64 = DispatchTime.now().uptimeNanoseconds

    init(password: String, minPacketSize: Int, maxPacketSize: Int) {
        self.inner = SalamanderObfuscator(password: password)
        // Parsers normalize already; clamp defensively in case an obfuscator is built directly.
        let sizes = HysteriaObfuscation.normalizedGeckoSizes(min: minPacketSize, max: maxPacketSize)
        self.minPacketSize = sizes.min
        self.maxPacketSize = sizes.max
    }

    // MARK: Seal

    func seal(_ packet: UnsafeRawBufferPointer) -> [Data] {
        guard !packet.isEmpty else { return [] }
        // Only long-header packets (high bit set) are fragmented; 1-RTT data rides Salamander alone.
        guard packet[0] & Self.fragmentFlag != 0 else { return inner.seal(packet) }

        let chunks = Int.random(in: Self.minChunks...Self.maxChunks)
        let chunkSize = packet.count / chunks
        msgIDCounter &+= 1
        let msgID = msgIDCounter

        var result: [Data] = []
        result.reserveCapacity(chunks)
        for index in 0..<chunks {
            let start = index * chunkSize
            let end = (index < chunks - 1) ? start + chunkSize : packet.count
            let chunkLength = end - start
            let padLength = randomPadLength(chunkLength: chunkLength)

            var frame = [UInt8]()
            frame.reserveCapacity(Self.headerLength + Int(padLength) + chunkLength)
            frame.append(Self.fragmentFlag)
            frame.append(msgID)
            frame.append(UInt8(index) << 4 | (UInt8(chunks) & 0x0f))
            frame.append(UInt8(padLength >> 8))
            frame.append(UInt8(padLength & 0xff))
            if padLength > 0 {
                var pad = [UInt8](repeating: 0, count: Int(padLength))
                _ = SecRandomCopyBytes(kSecRandomDefault, pad.count, &pad)
                frame.append(contentsOf: pad)
            }
            for offset in start..<end { frame.append(packet[offset]) }

            frame.withUnsafeBytes { result.append(contentsOf: inner.seal($0)) }
        }
        return result
    }

    /// Pads a chunk so the on-wire datagram (salt + header + padding + chunk) lands within the
    /// configured size window; returns 0 when even the unpadded packet already exceeds the max.
    private func randomPadLength(chunkLength: Int) -> UInt16 {
        let base = SalamanderObfuscator.saltLength + Self.headerLength + chunkLength
        let lo = Swift.max(minPacketSize, base)
        guard lo <= maxPacketSize else { return 0 }
        return UInt16(lo - base + Int.random(in: 0...(maxPacketSize - lo)))
    }

    // MARK: Open

    func open(_ datagram: Data) -> Data? {
        guard let opened = inner.open(datagram), let first = opened.first else { return nil }
        // 1-RTT (short header) passes straight through.
        guard first & Self.fragmentFlag != 0 else { return opened }

        let bytes = [UInt8](opened)
        guard bytes.count >= Self.headerLength else { return nil }
        let msgID = bytes[1]
        let chunkIdx = Int(bytes[2] >> 4)
        let totalChunks = Int(bytes[2] & 0x0f)
        let padLength = Int(bytes[3]) << 8 | Int(bytes[4])
        guard totalChunks >= Self.minChunks, totalChunks <= Self.maxChunks,
              chunkIdx < totalChunks else { return nil }
        let payloadStart = Self.headerLength + padLength
        guard payloadStart <= bytes.count else { return nil }

        let payload = Array(bytes[payloadStart...])
        return acceptChunk(msgID: msgID, chunkIdx: chunkIdx, totalChunks: totalChunks, payload: payload)
    }

    /// Stores a fragment and, once every chunk of a message has arrived, returns the reassembled
    /// QUIC packet. Returns `nil` while the message is incomplete or on a duplicate/invalid chunk.
    private func acceptChunk(msgID: UInt8, chunkIdx: Int, totalChunks: Int, payload: [UInt8]) -> Data? {
        let now = DispatchTime.now().uptimeNanoseconds
        if now &- lastSweep >= Self.sweepIntervalNanos {
            sweepExpired(now: now)
        }

        var entry = reassembly[msgID]
        // A reused (wrapped) msgID with a different chunk count restarts the slot.
        if let existing = entry, existing.total != totalChunks {
            reassembly[msgID] = nil
            entry = nil
        }

        let active: Reassembly
        if let entry {
            active = entry
        } else {
            if reassembly.count >= Self.maxReassembly { evictOldest() }
            active = Reassembly(total: totalChunks, deadline: now &+ Self.reassemblyTTLNanos)
            reassembly[msgID] = active
        }

        guard chunkIdx < active.chunks.count, active.chunks[chunkIdx] == nil else { return nil }
        active.chunks[chunkIdx] = payload
        active.received += 1
        guard active.received >= active.total else { return nil }

        reassembly[msgID] = nil
        var out = [UInt8]()
        for chunk in active.chunks where chunk != nil { out.append(contentsOf: chunk!) }
        return Data(out)
    }

    private func sweepExpired(now: UInt64) {
        reassembly = reassembly.filter { $0.value.deadline >= now }
        lastSweep = now
    }

    private func evictOldest() {
        if let oldest = reassembly.min(by: { $0.value.deadline < $1.value.deadline })?.key {
            reassembly[oldest] = nil
        }
    }
}
