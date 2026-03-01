//
//  VLESSProtocol.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

/// VLESS command types
enum VLESSCommand: UInt8 {
    case tcp = 0x01
    case udp = 0x02
    case mux = 0x03
}

/// VLESS address types
enum VLESSAddressType: UInt8 {
    case ipv4 = 0x01
    case domain = 0x02
    case ipv6 = 0x03
}

/// VLESS protocol encoder/decoder
struct VLESSProtocol {

    /// VLESS protocol version (always 0).
    static let version: UInt8 = 0

    /// Encode VLESS addons (protobuf format)
    /// Addons message: { string Flow = 1; bytes Seed = 2; }
    private static func encodeAddons(flow: String?) -> Data {
        guard let flow = flow, !flow.isEmpty else {
            return Data()
        }

        var data = Data()
        // Field 1 (Flow): wire type 2 (length-delimited), tag = 0x0A
        data.append(0x0A)
        // Length of string (varint)
        let flowBytes = flow.data(using: .utf8) ?? Data()
        data.append(UInt8(flowBytes.count))
        // String bytes
        data.append(flowBytes)
        return data
    }

    /// Encode a VLESS request header.
    ///
    /// In the Network Extension target, uses an optimized C implementation for
    /// simple TCP/UDP headers (no flow, no mux). Falls back to pure Swift otherwise.
    ///
    /// Format:
    /// - 1 byte: Version (0x00)
    /// - 16 bytes: UUID
    /// - 1 byte: Addons length (0 for no addons)
    /// - 1 byte: Command (TCP=0x01, UDP=0x02)
    /// - 2 bytes: Port (big-endian)
    /// - 1 byte: Address type
    /// - Variable: Address data
    static func encodeRequestHeader(
        uuid: UUID,
        command: VLESSCommand,
        destinationAddress: String,
        destinationPort: UInt16,
        flow: String? = nil
    ) -> Data {
        #if NETWORK_EXTENSION
        // If flow is specified or command is mux, use Swift implementation
        // (C doesn't support addons, and mux omits address/port)
        if (flow != nil && !flow!.isEmpty) || command == .mux {
            return encodeRequestHeaderSwift(uuid: uuid, command: command,
                                            destinationAddress: destinationAddress,
                                            destinationPort: destinationPort,
                                            flow: flow)
        }

        // Max header size: 1 + 16 + 1 + 1 + 2 + 1 + 1 + 255 = 278 bytes
        var buffer = [UInt8](repeating: 0, count: 278)

        // Get UUID bytes
        let uuidBytes = uuid.uuid
        let uuidArray: [UInt8] = [
            uuidBytes.0, uuidBytes.1, uuidBytes.2, uuidBytes.3,
            uuidBytes.4, uuidBytes.5, uuidBytes.6, uuidBytes.7,
            uuidBytes.8, uuidBytes.9, uuidBytes.10, uuidBytes.11,
            uuidBytes.12, uuidBytes.13, uuidBytes.14, uuidBytes.15
        ]

        // Parse address using C function
        var addressType: UInt8 = 0
        var addressBytes = [UInt8](repeating: 0, count: 256)
        var addressLen: Int = 0

        let headerLen: Int = destinationAddress.withCString { cStr in
            let strLen = strlen(cStr)

            let parseResult = parse_vless_address(cStr, strLen,
                                                   &addressType, &addressBytes, &addressLen)
            guard parseResult != 0 else {
                // Fallback: treat as domain
                addressType = UInt8(VLESS_ADDR_DOMAIN)
                addressLen = min(strLen, 255)
                memcpy(&addressBytes, cStr, addressLen)
                return 0
            }

            // Build header using C function
            return uuidArray.withUnsafeBufferPointer { uuidPtr in
                addressBytes.withUnsafeBufferPointer { addrPtr in
                    Int(build_vless_request_header(
                        &buffer,
                        uuidPtr.baseAddress!,
                        command.rawValue,
                        destinationPort,
                        addressType,
                        addrPtr.baseAddress!,
                        addressLen
                    ))
                }
            }
        }

        if headerLen > 0 {
            return Data(buffer.prefix(headerLen))
        }

        // Fallback to Swift implementation if C parsing failed
        return encodeRequestHeaderSwift(uuid: uuid, command: command,
                                        destinationAddress: destinationAddress,
                                        destinationPort: destinationPort,
                                        flow: nil)
        #else
        return encodeRequestHeaderSwift(uuid: uuid, command: command,
                                        destinationAddress: destinationAddress,
                                        destinationPort: destinationPort,
                                        flow: flow)
        #endif
    }

    /// Swift fallback implementation
    private static func encodeRequestHeaderSwift(
        uuid: UUID,
        command: VLESSCommand,
        destinationAddress: String,
        destinationPort: UInt16,
        flow: String?
    ) -> Data {
        var data = Data()

        // Version (1 byte)
        data.append(Self.version)

        // UUID (16 bytes)
        let uuidBytes = uuid.uuid
        data.append(contentsOf: [
            uuidBytes.0, uuidBytes.1, uuidBytes.2, uuidBytes.3,
            uuidBytes.4, uuidBytes.5, uuidBytes.6, uuidBytes.7,
            uuidBytes.8, uuidBytes.9, uuidBytes.10, uuidBytes.11,
            uuidBytes.12, uuidBytes.13, uuidBytes.14, uuidBytes.15
        ])

        // Addons (protobuf encoded)
        let addons = encodeAddons(flow: flow)
        data.append(UInt8(addons.count))
        if !addons.isEmpty {
            data.append(addons)
        }

        // Command (1 byte)
        data.append(command.rawValue)

        // Mux command omits address/port (matching Xray-core encoding.go:50-54)
        if command != .mux {
            // Port (2 bytes, big-endian)
            data.append(UInt8(destinationPort >> 8))
            data.append(UInt8(destinationPort & 0xFF))

            // Address
            if let ipv4 = parseIPv4(destinationAddress) {
                // IPv4 address
                data.append(VLESSAddressType.ipv4.rawValue)
                data.append(contentsOf: ipv4)
            } else if let ipv6 = parseIPv6(destinationAddress) {
                // IPv6 address
                data.append(VLESSAddressType.ipv6.rawValue)
                data.append(contentsOf: ipv6)
            } else {
                // Domain name
                let domainData = destinationAddress.data(using: .utf8) ?? Data()
                data.append(VLESSAddressType.domain.rawValue)
                data.append(UInt8(domainData.count))
                data.append(domainData)
            }
        }

        return data
    }

    /// Decode a VLESS response header
    /// Format:
    /// - 1 byte: Version (0x00)
    /// - 1 byte: Addons length
    /// - N bytes: Addons (if any)
    /// Returns the number of bytes consumed, or 0 if no response header present
    static func decodeResponseHeader(data: Data) throws -> Int {
        guard data.count >= 2 else {
            // Not enough data - could be no header, return 0
            return 0
        }

        let startIdx = data.startIndex
        let version = data[startIdx]

        // If version is not 0, there's no VLESS response header
        // The server is sending data directly (common with Reality/XTLS)
        guard version == Self.version else {
            return 0
        }

        let addonsLength = Int(data[data.index(startIdx, offsetBy: 1)])
        let totalLength = 2 + addonsLength

        guard data.count >= totalLength else {
            // Not enough data for addons yet
            return 0
        }

        return totalLength
    }

    /// Parse an IPv4 address string into bytes
    private static func parseIPv4(_ address: String) -> [UInt8]? {
        let parts = address.split(separator: ".")
        guard parts.count == 4 else { return nil }

        var bytes: [UInt8] = []
        for part in parts {
            guard let byte = UInt8(part) else { return nil }
            bytes.append(byte)
        }
        return bytes
    }

    /// Parse an IPv6 address string into bytes
    private static func parseIPv6(_ address: String) -> [UInt8]? {
        // Handle bracketed IPv6 addresses
        var addr = address
        if addr.hasPrefix("[") && addr.hasSuffix("]") {
            addr = String(addr.dropFirst().dropLast())
        }

        // Simple IPv6 parsing - expand :: and parse
        var parts = addr.split(separator: ":", omittingEmptySubsequences: false).map(String.init)

        // Handle :: expansion
        if let emptyIndex = parts.firstIndex(of: "") {
            let before = Array(parts[..<emptyIndex])
            let after = Array(parts[(emptyIndex + 1)...]).filter { !$0.isEmpty }
            let missing = 8 - before.count - after.count
            if missing < 0 { return nil }
            parts = before + Array(repeating: "0", count: missing) + after
        }

        guard parts.count == 8 else { return nil }

        var bytes: [UInt8] = []
        for part in parts {
            guard let value = UInt16(part, radix: 16) else { return nil }
            bytes.append(UInt8(value >> 8))
            bytes.append(UInt8(value & 0xFF))
        }

        return bytes
    }
}
