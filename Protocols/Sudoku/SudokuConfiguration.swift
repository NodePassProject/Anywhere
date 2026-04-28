//
//  SudokuConfiguration.swift
//  Anywhere
//
//  Copyright (C) 2026 by saba <contact me via issue>. GPLv3.
//  Created by saba on 4/23/26.
//

import Foundation

enum SudokuAEADMethod: String, CaseIterable, Codable, Hashable {
    case chacha20Poly1305 = "chacha20-poly1305"
    case aes128GCM = "aes-128-gcm"
    case none = "none"

    var displayName: String {
        switch self {
        case .chacha20Poly1305:
            "ChaCha20-Poly1305"
        case .aes128GCM:
            "AES-128-GCM"
        case .none:
            "None"
        }
    }
}

enum SudokuASCIIMode: String, CaseIterable, Codable, Hashable {
    case preferEntropy = "prefer_entropy"
    case preferASCII = "prefer_ascii"
    case upASCIIToDownEntropy = "up_ascii_down_entropy"
    case upEntropyToDownASCII = "up_entropy_down_ascii"

    init?(normalized value: String) {
        let raw = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch raw {
        case "", "entropy", "prefer_entropy":
            self = .preferEntropy
        case "ascii", "prefer_ascii":
            self = .preferASCII
        case "up_ascii_down_entropy":
            self = .upASCIIToDownEntropy
        case "up_entropy_down_ascii":
            self = .upEntropyToDownASCII
        default:
            return nil
        }
    }

    var displayName: String {
        switch self {
        case .preferEntropy:
            "Prefer Entropy"
        case .preferASCII:
            "Prefer ASCII"
        case .upASCIIToDownEntropy:
            "Up ASCII / Down Entropy"
        case .upEntropyToDownASCII:
            "Up Entropy / Down ASCII"
        }
    }

    var shortLinkToken: String {
        switch self {
        case .preferEntropy:
            "entropy"
        case .preferASCII:
            "ascii"
        case .upASCIIToDownEntropy, .upEntropyToDownASCII:
            rawValue
        }
    }
}

enum SudokuHTTPMaskMode: String, CaseIterable, Codable, Hashable {
    case legacy
    case stream
    case poll
    case auto
    case ws

    var displayName: String {
        switch self {
        case .legacy:
            "Legacy"
        case .stream:
            "Stream"
        case .poll:
            "Poll"
        case .auto:
            "Auto"
        case .ws:
            "WebSocket"
        }
    }
}

enum SudokuHTTPMaskMultiplex: String, CaseIterable, Codable, Hashable {
    case off
    case auto
    case on

    var displayName: String { rawValue.uppercased() }
}

struct SudokuHTTPMaskConfiguration: Codable, Hashable {
    var disable: Bool
    var mode: SudokuHTTPMaskMode
    var tls: Bool
    var host: String
    var pathRoot: String
    var multiplex: SudokuHTTPMaskMultiplex

    init(
        disable: Bool = false,
        mode: SudokuHTTPMaskMode = .legacy,
        tls: Bool = false,
        host: String = "",
        pathRoot: String = "",
        multiplex: SudokuHTTPMaskMultiplex = .off
    ) {
        self.disable = disable
        self.mode = mode
        self.tls = tls
        self.host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        self.pathRoot = SudokuHTTPMaskConfiguration.normalizePathRoot(pathRoot)
        self.multiplex = disable ? .off : multiplex
    }

    static func normalizePathRoot(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard !trimmed.isEmpty else { return "" }
        let isAllowed: (UInt8) -> Bool = {
            ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 95 || $0 == 45
        }
        guard trimmed.utf8.allSatisfy(isAllowed) else { return "" }
        return trimmed
    }
}

struct SudokuConfiguration: Codable, Hashable {
    var key: String
    var aeadMethod: SudokuAEADMethod
    var paddingMin: Int
    var paddingMax: Int
    var asciiMode: SudokuASCIIMode
    var customTables: [String]
    var enablePureDownlink: Bool
    var httpMask: SudokuHTTPMaskConfiguration

    init(
        key: String,
        aeadMethod: SudokuAEADMethod = .chacha20Poly1305,
        paddingMin: Int = 5,
        paddingMax: Int = 15,
        asciiMode: SudokuASCIIMode = .preferEntropy,
        customTables: [String] = [],
        enablePureDownlink: Bool = true,
        httpMask: SudokuHTTPMaskConfiguration = .init()
    ) {
        self.key = key.trimmingCharacters(in: .whitespacesAndNewlines)
        self.aeadMethod = aeadMethod
        self.paddingMin = max(0, min(100, paddingMin))
        self.paddingMax = max(self.paddingMin, min(100, paddingMax))
        self.asciiMode = asciiMode
        self.customTables = Self.normalizeCustomTables(customTables)
        self.enablePureDownlink = enablePureDownlink
        self.httpMask = httpMask
    }

    private enum CodingKeys: String, CodingKey {
        case key
        case aeadMethod
        case paddingMin
        case paddingMax
        case asciiMode
        case customTable
        case customTables
        case enablePureDownlink
        case httpMask
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let legacyCustomTable = try container.decodeIfPresent(String.self, forKey: .customTable) ?? ""
        let decodedCustomTables = try container.decodeIfPresent([String].self, forKey: .customTables) ?? []

        self.init(
            key: try container.decode(String.self, forKey: .key),
            aeadMethod: try container.decodeIfPresent(SudokuAEADMethod.self, forKey: .aeadMethod) ?? .chacha20Poly1305,
            paddingMin: try container.decodeIfPresent(Int.self, forKey: .paddingMin) ?? 5,
            paddingMax: try container.decodeIfPresent(Int.self, forKey: .paddingMax) ?? 15,
            asciiMode: try container.decodeIfPresent(SudokuASCIIMode.self, forKey: .asciiMode) ?? .preferEntropy,
            customTables: Self.normalizeCustomTables(decodedCustomTables, legacy: legacyCustomTable),
            enablePureDownlink: try container.decodeIfPresent(Bool.self, forKey: .enablePureDownlink) ?? true,
            httpMask: try container.decodeIfPresent(SudokuHTTPMaskConfiguration.self, forKey: .httpMask) ?? .init()
        )
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(key, forKey: .key)
        try container.encode(aeadMethod, forKey: .aeadMethod)
        try container.encode(paddingMin, forKey: .paddingMin)
        try container.encode(paddingMax, forKey: .paddingMax)
        try container.encode(asciiMode, forKey: .asciiMode)
        try container.encode(customTables, forKey: .customTables)
        try container.encode(enablePureDownlink, forKey: .enablePureDownlink)
        try container.encode(httpMask, forKey: .httpMask)
    }

    static func normalizeCustomTables(_ tables: [String], legacy: String = "") -> [String] {
        var seen = Set<String>()
        var normalized: [String] = []
        let trimmedLegacy = legacy.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedLegacy.isEmpty {
            normalized.append(trimmedLegacy)
            seen.insert(trimmedLegacy)
        }
        for table in tables {
            let trimmed = table.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty || !seen.insert(trimmed).inserted {
                continue
            }
            normalized.append(trimmed)
        }
        return normalized
    }
}
