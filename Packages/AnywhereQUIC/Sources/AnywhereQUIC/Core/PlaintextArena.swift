//
//  PlaintextArena.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/6/26.
//

import Foundation

struct PlaintextArena {
    static let packetsPerChunk = 4

    private let chunkCapacity: Int
    private var chunk: Data?
    private var base: UnsafeMutableRawPointer?
    private var used = 0
    private var reserved = 0
    private var isSliced = false

    init(packetCapacity: Int) {
        self.chunkCapacity = packetCapacity * Self.packetsPerChunk
    }

    mutating func region(count: Int) -> UnsafeMutableRawBufferPointer {
        if self.isSliced {
            self.used += self.reserved
            self.isSliced = false
        }
        if self.base == nil || self.used + count > self.chunkCapacity {
            let capacity = Swift.max(self.chunkCapacity, count)
            let base = malloc(capacity)!
            self.chunk = Data(bytesNoCopy: base, count: capacity, deallocator: .free)
            self.base = base
            self.used = 0
        }
        self.reserved = count
        return UnsafeMutableRawBufferPointer(start: self.base! + self.used, count: count)
    }

    mutating func slice(_ bytes: UnsafeRawBufferPointer) -> Data? {
        guard let chunk = self.chunk, let base = self.base, let start = bytes.baseAddress else {
            return nil
        }
        let offset = UnsafeRawPointer(start) - UnsafeRawPointer(base)
        guard offset >= self.used, offset + bytes.count <= self.used + self.reserved else {
            return nil
        }
        self.isSliced = true
        return chunk[offset..<offset + bytes.count]
    }
}
