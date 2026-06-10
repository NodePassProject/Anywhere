//
//  VLESSProtocol.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

enum ProxyCommand: UInt8 {
    case tcp = 0x01
    case udp = 0x02
    case mux = 0x03
}

enum VLESSAddressType: UInt8 {
    case ipv4 = 0x01
    case domain = 0x02
    case ipv6 = 0x03
}

struct VLESSProtocol {

    /// VLESS protocol version (always 0).
    static let version: UInt8 = 0

    /// Encode VLESS addons. Protobuf schema: `{ string Flow = 1; bytes Seed = 2; }`
    private static func encodeAddons(flow: String?) -> Data {
        guard let flow = flow, !flow.isEmpty else {
            return Data()
        }

        var data = Data()
        // Field 1 (Flow): wire type 2 (length-delimited), tag = 0x0A
        data.append(0x0A)
        let flowBytes = flow.data(using: .utf8) ?? Data()
        data.append(UInt8(flowBytes.count))
        data.append(flowBytes)
        return data
    }

    /// Encode a VLESS request header.
    ///
    /// Wire format: version(1) | uuid(16) | addons-len(1) | addons(N) |
    /// command(1) | port-BE(2) | addr-type(1) | addr(variable)
    /// Mux command omits port and address.
    static func encodeRequestHeader(
        uuid: UUID,
        command: ProxyCommand,
        destinationAddress: String,
        destinationPort: UInt16,
        flow: String? = nil
    ) -> Data {
        return encodeRequestHeaderSwift(uuid: uuid, command: command,
                                        destinationAddress: destinationAddress,
                                        destinationPort: destinationPort,
                                        flow: flow)
    }

    private static func encodeRequestHeaderSwift(
        uuid: UUID,
        command: ProxyCommand,
        destinationAddress: String,
        destinationPort: UInt16,
        flow: String?
    ) -> Data {
        var data = Data()

        data.append(Self.version)

        let uuidBytes = uuid.uuid
        data.append(contentsOf: [
            uuidBytes.0, uuidBytes.1, uuidBytes.2, uuidBytes.3,
            uuidBytes.4, uuidBytes.5, uuidBytes.6, uuidBytes.7,
            uuidBytes.8, uuidBytes.9, uuidBytes.10, uuidBytes.11,
            uuidBytes.12, uuidBytes.13, uuidBytes.14, uuidBytes.15
        ])

        let addons = encodeAddons(flow: flow)
        data.append(UInt8(addons.count))
        if !addons.isEmpty {
            data.append(addons)
        }

        data.append(command.rawValue)

        if command != .mux {
            data.append(UInt8(destinationPort >> 8))
            data.append(UInt8(destinationPort & 0xFF))

            if let ipv4 = parseIPv4(destinationAddress) {
                data.append(VLESSAddressType.ipv4.rawValue)
                data.append(contentsOf: ipv4)
            } else if let ipv6 = parseIPv6(destinationAddress) {
                data.append(VLESSAddressType.ipv6.rawValue)
                data.append(contentsOf: ipv6)
            } else {
                let domainData = destinationAddress.data(using: .utf8) ?? Data()
                data.append(VLESSAddressType.domain.rawValue)
                data.append(UInt8(domainData.count))
                data.append(domainData)
            }
        }

        return data
    }

    /// Decode a VLESS response header. Returns bytes consumed, or 0 if absent.
    /// Wire format: version(1) | addons-len(1) | addons(N)
    static func decodeResponseHeader(data: Data) throws -> Int {
        guard data.count >= 2 else {
            return 0
        }

        let startIdx = data.startIndex
        let version = data[startIdx]

        // Non-zero version means no response header — the server sends data directly (Reality/XTLS).
        guard version == Self.version else {
            return 0
        }

        let addonsLength = Int(data[data.index(startIdx, offsetBy: 1)])
        let totalLength = 2 + addonsLength

        guard data.count >= totalLength else {
            return 0
        }

        return totalLength
    }

    private static func parseIPv4(_ address: String) -> [UInt8]? {
        var addr = in_addr()
        guard inet_pton(AF_INET, address, &addr) == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Array($0) }
    }

    /// Strips surrounding brackets (e.g. "[::1]") before parsing.
    private static func parseIPv6(_ address: String) -> [UInt8]? {
        var clean = address
        if clean.hasPrefix("[") && clean.hasSuffix("]") {
            clean = String(clean.dropFirst().dropLast())
        }
        var addr = in6_addr()
        guard inet_pton(AF_INET6, clean, &addr) == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Array($0) }
    }
}
