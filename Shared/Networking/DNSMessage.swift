//
//  DNSMessage.swift
//  Anywhere
//
//  Created by NodePassProject on 7/24/26.
//

import Foundation

nonisolated enum DNSMessage {

    static let typeA: UInt16 = 1
    static let typeAAAA: UInt16 = 28

    private static let classIN: UInt16 = 1
    private static let headerLength = 12

    // MARK: - Query
    
    static func makeQuery(domain: String, type: UInt16, id: UInt16) -> Data? {
        var message = Data(capacity: 32 + domain.utf8.count)
        message.append(contentsOf: [UInt8(id >> 8), UInt8(id & 0xFF)])
        message.append(contentsOf: [0x01, 0x00])    // RD=1, everything else clear
        message.append(contentsOf: [0x00, 0x01])    // QDCOUNT = 1
        message.append(contentsOf: [0x00, 0x00])    // ANCOUNT
        message.append(contentsOf: [0x00, 0x00])    // NSCOUNT
        message.append(contentsOf: [0x00, 0x00])    // ARCOUNT

        var labelCount = 0
        for label in domain.split(separator: ".") {
            let bytes = Array(label.utf8)
            guard !bytes.isEmpty, bytes.count <= 63, bytes.allSatisfy({ $0 < 0x80 }) else { return nil }
            message.append(UInt8(bytes.count))
            message.append(contentsOf: bytes)
            labelCount += 1
        }
        guard labelCount > 0 else { return nil }
        message.append(0)                           // root label

        message.append(contentsOf: [UInt8(type >> 8), UInt8(type & 0xFF)])
        message.append(contentsOf: [UInt8(classIN >> 8), UInt8(classIN & 0xFF)])
        
        guard message.count <= 512 else { return nil }
        return message
    }

    // MARK: - Response

    enum ParseFailure: Error, Equatable {
        case malformed
        /// Not an answer to the query that was sent.
        case identifierMismatch
        /// Non-zero RCODE, including NXDOMAIN (3).
        case serverFailure(rcode: UInt8)
    }
    
    static func parseAddresses(_ response: Data, expectedID: UInt16) throws(ParseFailure) -> [String] {
        let bytes = [UInt8](response)
        guard bytes.count >= headerLength else { throw .malformed }

        let id = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
        guard id == expectedID else { throw .identifierMismatch }
        guard bytes[2] & 0x80 != 0 else { throw .malformed }    // QR must be set

        let rcode = bytes[3] & 0x0F
        guard rcode == 0 else { throw .serverFailure(rcode: rcode) }

        let questionCount = Int(UInt16(bytes[4]) << 8 | UInt16(bytes[5]))
        let answerCount = Int(UInt16(bytes[6]) << 8 | UInt16(bytes[7]))

        var offset = headerLength
        for _ in 0..<questionCount {
            guard let afterName = skipName(bytes, from: offset) else { throw .malformed }
            offset = afterName + 4                              // QTYPE + QCLASS
            guard offset <= bytes.count else { throw .malformed }
        }

        var ipv4: [String] = []
        var ipv6: [String] = []
        for _ in 0..<answerCount {
            guard let afterName = skipName(bytes, from: offset) else { throw .malformed }
            offset = afterName
            guard offset + 10 <= bytes.count else { throw .malformed }

            let type = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
            let recordClass = UInt16(bytes[offset + 2]) << 8 | UInt16(bytes[offset + 3])
            let rdLength = Int(UInt16(bytes[offset + 8]) << 8 | UInt16(bytes[offset + 9]))
            offset += 10
            guard offset + rdLength <= bytes.count else { throw .malformed }

            if recordClass == classIN, type == typeA, rdLength == 4 {
                if let address = formatIPv4(Array(bytes[offset..<offset + 4])) { ipv4.append(address) }
            } else if recordClass == classIN, type == typeAAAA, rdLength == 16 {
                if let address = formatIPv6(Array(bytes[offset..<offset + 16])) { ipv6.append(address) }
            }
            offset += rdLength
        }

        return ipv4 + ipv6
    }

    // MARK: - Internal
    
    private static func skipName(_ bytes: [UInt8], from offset: Int) -> Int? {
        var cursor = offset

        while cursor < bytes.count {
            let length = Int(bytes[cursor])

            if length & 0xC0 == 0xC0 {
                guard cursor + 2 <= bytes.count else { return nil }
                let target = Int(UInt16(bytes[cursor] & 0x3F) << 8 | UInt16(bytes[cursor + 1]))
                // Pointers must point backwards into the header-adjacent region.
                guard target < cursor, target >= headerLength else { return nil }
                return cursor + 2
            }
            guard length & 0xC0 == 0 else { return nil }        // reserved label type

            cursor += 1
            if length == 0 { return cursor }                    // root label ends the name
            cursor += length
            guard cursor <= bytes.count else { return nil }
        }
        return nil
    }

    private static func formatIPv4(_ octets: [UInt8]) -> String? {
        var address = in_addr()
        memcpy(&address, octets, 4)
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &address, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else { return nil }
        return String(nulTerminated: buffer)
    }

    private static func formatIPv6(_ octets: [UInt8]) -> String? {
        var address = in6_addr()
        memcpy(&address, octets, 16)
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else { return nil }
        return String(nulTerminated: buffer)
    }
}
