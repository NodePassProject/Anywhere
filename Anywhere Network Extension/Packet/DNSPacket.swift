//
//  DNSPacket.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation

nonisolated enum DNSPacket {
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
        answerIP: [UInt8]?,
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

        var rdLength: UInt16 = 0
        var ansType: UInt16 = 0
        if answerIP != nil {
            if qtype == 1 {
                rdLength = 4
                ansType = 1
            } else if qtype == 28 {
                rdLength = 16
                ansType = 28
            }
        }

        if rdLength > 0, let ipBytes = answerIP {
            let answerRecLen = 12 + Int(rdLength)
            let responseLen = questionEnd + answerRecLen

            var response = Data(count: responseLen)
            response.withUnsafeMutableBytes { pointer in
                guard let p = pointer.bindMemory(to: UInt8.self).baseAddress,
                      let source = queryData.baseAddress else { return }

                memcpy(p, source, questionEnd)
                
                p[2] = 0x85
                p[3] = 0x80
                p[4] = 0x00
                p[5] = 0x01
                p[6] = 0x00
                p[7] = 0x01
                p[8] = 0x00
                p[9] = 0x00
                p[10] = 0x00
                p[11] = 0x00

                let answerOffset = questionEnd
                p[answerOffset + 0] = 0xC0
                p[answerOffset + 1] = 0x0C
                p[answerOffset + 2] = UInt8(ansType >> 8)
                p[answerOffset + 3] = UInt8(ansType & 0xFF)
                p[answerOffset + 4] = 0x00; p[answerOffset + 5] = 0x01
                p[answerOffset + 6] = UInt8((ttl >> 24) & 0xFF)
                p[answerOffset + 7] = UInt8((ttl >> 16) & 0xFF)
                p[answerOffset + 8] = UInt8((ttl >> 8) & 0xFF)
                p[answerOffset + 9] = UInt8(ttl & 0xFF)
                p[answerOffset + 10] = UInt8(rdLength >> 8)
                p[answerOffset + 11] = UInt8(rdLength & 0xFF)
                
                memcpy(p + answerOffset + 12, ipBytes, Int(rdLength))
            }
            return response
        } else {
            var response = Data(count: questionEnd)
            response.withUnsafeMutableBytes { pointer in
                guard let p = pointer.bindMemory(to: UInt8.self).baseAddress,
                      let source = queryData.baseAddress else { return }
                memcpy(p, source, questionEnd)
                p[2] = 0x85; p[3] = 0x80
                p[4] = 0x00; p[5] = 0x01
                p[6] = 0x00; p[7] = 0x00
                p[8] = 0x00; p[9] = 0x00; p[10] = 0x00; p[11] = 0x00
            }
            return response
        }
    }
}
