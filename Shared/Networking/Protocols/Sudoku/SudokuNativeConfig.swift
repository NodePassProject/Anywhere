//
//  SudokuNativeConfig.swift
//  Anywhere
//
//  Created by saba-futai on 10/18/26.
//

import Foundation
import Synchronization

nonisolated final class SudokuNativeConfig: Sendable {
    let serverHost: String
    let serverPort: UInt16
    let key: String
    let privateKey: Data?
    let aeadMethod: SudokuAEADMethod
    let paddingMin: Int32
    let paddingMax: Int32
    let asciiMode: String
    let customTables: [String]
    let selectedCustomTable: String
    let sendsTableHint: Bool
    let pureDownlink: Bool
    let multiplex: SudokuMultiplex
    let httpMask: SudokuHTTPMaskConfiguration

    init(configuration: ProxyConfiguration) throws {
        guard case .sudoku(let sudoku) = configuration.outbound else {
            throw AnywhereError.proxy(.sudoku, .invalidConfiguration(detail: "missing protocol settings"))
        }
        self.serverHost = configuration.serverAddress
        self.serverPort = configuration.serverPort
        self.aeadMethod = sudoku.aeadMethod
        self.paddingMin = Int32(sudoku.paddingMin)
        self.paddingMax = Int32(sudoku.paddingMax)
        self.asciiMode = sudoku.asciiMode.rawValue
        self.customTables = sudoku.customTables
        if sudoku.customTables.isEmpty {
            self.selectedCustomTable = ""
            self.sendsTableHint = false
        } else {
            let index: Int
            if sudoku.customTables.count == 1 {
                index = 0
            } else {
                index = Int(try SudokuNativeCrypto.randomData(count: 1)[0]) % sudoku.customTables.count
            }
            self.selectedCustomTable = sudoku.customTables[index]
            self.sendsTableHint = sudoku.customTables.count > 1
        }
        self.pureDownlink = sudoku.enablePureDownlink
        self.multiplex = sudoku.multiplex
        self.httpMask = sudoku.httpMask

        if let raw = Data(hexString: sudoku.key), raw.count == 32 || raw.count == 64 {
            self.privateKey = raw
        } else {
            self.privateKey = nil
        }
        self.key = SudokuKeyRecovery.recoverPublicKeyHex(sudoku.key) ?? sudoku.key
    }

    var nativeMuxEnabled: Bool {
        multiplex == .on
    }
}

nonisolated private struct SudokuTableCacheKey: Hashable {
    let key: String
    let asciiMode: String
    let customTable: String
}

nonisolated private enum SudokuTableCache {
    private static let maxEntries = 16

    private struct State {
        var pairs: [SudokuTableCacheKey: SudokuTablePair] = [:]
        var accessOrder: [SudokuTableCacheKey] = []
    }

    private static let state = Mutex(State())

    static func pair(for config: SudokuNativeConfig) throws -> SudokuTablePair {
        let cacheKey = SudokuTableCacheKey(
            key: config.key,
            asciiMode: config.asciiMode,
            customTable: config.selectedCustomTable
        )
        if let cached = state.withLock({ (state: inout State) -> SudokuTablePair? in
            guard let pair = state.pairs[cacheKey] else { return nil }
            touch(cacheKey, in: &state)
            return pair
        }) {
            return cached
        }
        
        let built = try SudokuTablePair(
            key: config.key,
            asciiMode: config.asciiMode,
            customUplink: config.selectedCustomTable,
            customDownlink: config.selectedCustomTable
        )
        return state.withLock { (state: inout State) -> SudokuTablePair in
            if let existing = state.pairs[cacheKey] {
                touch(cacheKey, in: &state)
                return existing
            }
            state.pairs[cacheKey] = built
            touch(cacheKey, in: &state)
            trimIfNeeded(in: &state)
            return built
        }
    }

    private static func touch(_ key: SudokuTableCacheKey, in state: inout State) {
        state.accessOrder.removeAll { $0 == key }
        state.accessOrder.append(key)
    }

    private static func trimIfNeeded(in state: inout State) {
        while state.accessOrder.count > maxEntries, let evicted = state.accessOrder.first {
            state.accessOrder.removeFirst()
            state.pairs.removeValue(forKey: evicted)
        }
    }
}

nonisolated final class SudokuTables: Sendable {
    private let pair: SudokuTablePair
    let sendsTableHint: Bool

    init(config: SudokuNativeConfig) throws {
        sendsTableHint = config.sendsTableHint
        pair = try SudokuTableCache.pair(for: config)
    }

    func withUplink<T>(_ body: (SudokuTable) throws -> T) rethrows -> T {
        try body(pair.uplink)
    }

    func withDownlink<T>(_ body: (SudokuTable) throws -> T) rethrows -> T {
        try body(pair.downlink)
    }

    var hint: UInt32 { pair.uplink.hint }
}
