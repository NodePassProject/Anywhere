//
//  DNSPacket.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation

nonisolated enum DNSPacket {
    private static let maxUDPResponseLength = 512

    static func parseQuery(_ data: UnsafeBufferPointer<UInt8>) -> (domain: String, qtype: UInt16)? {
        guard data.count >= 12 else { return nil }

        let qdcount = UInt16(data[4]) << 8 | UInt16(data[5])
        guard qdcount > 0 else { return nil }

        var offset = 12
        var domainBytes = [UInt8]()
        domainBytes.reserveCapacity(64)
        var labelCount = 0

        while offset < data.count {
            let labelLen = Int(data[offset])
            offset += 1

            if labelLen == 0 { break }
            
            guard labelLen & 0xC0 == 0 else { return nil }
            guard offset + labelLen <= data.count else { return nil }

            if labelCount > 0 { domainBytes.append(0x2E) }
            domainBytes.append(contentsOf: UnsafeBufferPointer(start: data.baseAddress! + offset, count: labelLen))
            guard domainBytes.count <= 253 else { return nil }
            labelCount += 1
            offset += labelLen
        }

        guard labelCount > 0 else { return nil }
        
        guard offset + 2 <= data.count else { return nil }
        let qtype = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])

        let domain = String(bytes: domainBytes, encoding: .ascii) ?? ""
        return (domain, qtype)
    }
    
    static func generateResponse(
        query queryData: UnsafeBufferPointer<UInt8>,
        answerIPs: [[UInt8]],
        qtype: UInt16,
        ttl: UInt32 = TunnelConstants.dnsSyntheticAddressAnswerTTL
    ) -> Data? {
        guard queryData.count >= 12 else { return nil }

        var offset = 12
        while offset < queryData.count {
            let labelLen = Int(queryData[offset])
            offset += 1
            if labelLen == 0 { break }
            if labelLen & 0xC0 != 0 { break }
            offset += labelLen
        }
        offset += 4
        guard offset <= queryData.count else { return nil }

        let questionEnd = offset

        let rdLength: Int
        switch qtype {
        case 1: rdLength = 4
        case 28: rdLength = 16
        default: rdLength = 0
        }
        let answerRecordLength = 12 + rdLength
        let capacity = rdLength > 0 ? max((maxUDPResponseLength - questionEnd) / answerRecordLength, 0) : 0
        let answers = Array(answerIPs.lazy.filter { $0.count == rdLength }.prefix(capacity))

        var response = Data(count: questionEnd + answers.count * answerRecordLength)
        response.withUnsafeMutableBytes { pointer in
            guard let p = pointer.bindMemory(to: UInt8.self).baseAddress,
                  let source = queryData.baseAddress else { return }

            memcpy(p, source, questionEnd)

            p[2] = 0x85
            p[3] = 0x80
            p[4] = 0x00
            p[5] = 0x01
            p[6] = UInt8(answers.count >> 8)
            p[7] = UInt8(answers.count & 0xFF)
            p[8] = 0x00
            p[9] = 0x00
            p[10] = 0x00
            p[11] = 0x00

            var cursor = questionEnd
            for ip in answers {
                p[cursor + 0] = 0xC0
                p[cursor + 1] = 0x0C
                p[cursor + 2] = UInt8(qtype >> 8)
                p[cursor + 3] = UInt8(qtype & 0xFF)
                p[cursor + 4] = 0x00; p[cursor + 5] = 0x01
                p[cursor + 6] = UInt8((ttl >> 24) & 0xFF)
                p[cursor + 7] = UInt8((ttl >> 16) & 0xFF)
                p[cursor + 8] = UInt8((ttl >> 8) & 0xFF)
                p[cursor + 9] = UInt8(ttl & 0xFF)
                p[cursor + 10] = UInt8(rdLength >> 8)
                p[cursor + 11] = UInt8(rdLength & 0xFF)
                ip.withUnsafeBufferPointer { bytes in
                    if let base = bytes.baseAddress { memcpy(p + cursor + 12, base, rdLength) }
                }
                cursor += answerRecordLength
            }
        }
        return response
    }
}
