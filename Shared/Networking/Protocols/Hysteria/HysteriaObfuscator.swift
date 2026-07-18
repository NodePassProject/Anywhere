//
//  HysteriaObfuscator.swift
//  Anywhere
//
//  Created by NodePassProject on 6/23/26.
//

import Foundation
import Security
import Synchronization

// MARK: - Salamander

/// XOR obfuscation: every datagram is `salt(8) || (packet XOR keystream)`, where the keystream is
/// BLAKE2b-256 over `password || salt` cycled to the packet length.
nonisolated final class SalamanderObfuscator: QUICPacketObfuscator {
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
nonisolated final class GeckoObfuscator: QUICPacketObfuscator {
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
    private let msgIDCounter = Atomic<UInt8>(0)

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

    private struct ReassemblyTable {
        /// Keyed by `msgID`.
        var entries: [UInt8: Reassembly] = [:]
        var lastSweep: UInt64
    }
    /// All reassembly state; `Reassembly` instances are only ever touched under this lock.
    private let table: Mutex<ReassemblyTable>

    init(password: String, minPacketSize: Int, maxPacketSize: Int) {
        self.inner = SalamanderObfuscator(password: password)
        let sizes = HysteriaObfuscation.normalizedGeckoSizes(min: minPacketSize, max: maxPacketSize)
        self.minPacketSize = sizes.min
        self.maxPacketSize = sizes.max
        self.table = Mutex(ReassemblyTable(lastSweep: DispatchTime.now().uptimeNanoseconds))
    }

    // MARK: Seal

    func seal(_ packet: UnsafeRawBufferPointer) -> [Data] {
        guard !packet.isEmpty else { return [] }
        // Only long-header packets (high bit set) are fragmented; 1-RTT data rides Salamander alone.
        guard packet[0] & Self.fragmentFlag != 0 else { return inner.seal(packet) }

        let chunks = Int.random(in: Self.minChunks...Self.maxChunks)
        let chunkSize = packet.count / chunks
        let msgID = msgIDCounter.wrappingAdd(1, ordering: .relaxed).newValue

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
    
    private func acceptChunk(msgID: UInt8, chunkIdx: Int, totalChunks: Int, payload: [UInt8]) -> Data? {
        table.withLock { table in
            let now = DispatchTime.now().uptimeNanoseconds
            if now &- table.lastSweep >= Self.sweepIntervalNanos {
                table.entries = table.entries.filter { $0.value.deadline >= now }
                table.lastSweep = now
            }

            var entry = table.entries[msgID]
            if let existing = entry, existing.total != totalChunks {
                table.entries[msgID] = nil
                entry = nil
            }

            let active: Reassembly
            if let entry {
                active = entry
            } else {
                if table.entries.count >= Self.maxReassembly,
                   let oldest = table.entries.min(by: { $0.value.deadline < $1.value.deadline })?.key {
                    table.entries[oldest] = nil
                }
                active = Reassembly(total: totalChunks, deadline: now &+ Self.reassemblyTTLNanos)
                table.entries[msgID] = active
            }

            guard chunkIdx < active.chunks.count, active.chunks[chunkIdx] == nil else { return nil }
            active.chunks[chunkIdx] = payload
            active.received += 1
            guard active.received >= active.total else { return nil }

            table.entries[msgID] = nil
            var out = [UInt8]()
            for chunk in active.chunks where chunk != nil { out.append(contentsOf: chunk!) }
            return Data(out)
        }
    }
}
