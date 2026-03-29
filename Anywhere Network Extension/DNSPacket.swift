//
//  DNSPacket.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/8/26.
//

import Foundation

enum DNSPacket {

    /// Parse a DNS query to extract the queried domain name and QTYPE.
    /// Returns (domain, qtype) or nil on failure.
    static func parseQuery(_ data: UnsafeBufferPointer<UInt8>) -> (domain: String, qtype: UInt16)? {
        // DNS header is 12 bytes
        guard data.count >= 12 else { return nil }

        // Check QDCOUNT >= 1
        let qdcount = UInt16(data[4]) << 8 | UInt16(data[5])
        guard qdcount > 0 else { return nil }

        // Parse QNAME starting at byte 12 — collect raw bytes, convert to String once
        var offset = 12
        var domainBytes = [UInt8]()
        domainBytes.reserveCapacity(64)
        var labelCount = 0

        while offset < data.count {
            let labelLen = Int(data[offset])
            offset += 1

            if labelLen == 0 { break }

            // Compressed pointers not expected in queries
            guard labelLen & 0xC0 == 0 else { return nil }
            guard offset + labelLen <= data.count else { return nil }

            if labelCount > 0 { domainBytes.append(0x2E) } // "."
            domainBytes.append(contentsOf: UnsafeBufferPointer(start: data.baseAddress! + offset, count: labelLen))
            labelCount += 1
            offset += labelLen
        }

        guard labelCount > 0 else { return nil }

        // Read QTYPE: 2 bytes after QNAME terminator
        guard offset + 2 <= data.count else { return nil }
        let qtype = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])

        let domain = String(bytes: domainBytes, encoding: .ascii) ?? ""
        return (domain, qtype)
    }

    /// Generate a minimal DNS response for a query.
    /// For QTYPE=A (1):    if fakeIP is non-nil, returns A record (RDLENGTH=4, TTL=1).
    /// For QTYPE=AAAA (28): if fakeIP is non-nil, returns AAAA record (RDLENGTH=16, TTL=1).
    /// If fakeIP is nil or QTYPE is neither A nor AAAA: returns NODATA (ANCOUNT=0).
    static func generateResponse(query queryData: UnsafeBufferPointer<UInt8>,
                                 fakeIP: [UInt8]?, qtype: UInt16) -> Data? {
        guard queryData.count >= 12 else { return nil }

        // Find the end of the question section
        var offset = 12
        while offset < queryData.count {
            let labelLen = Int(queryData[offset])
            offset += 1
            if labelLen == 0 { break }
            if labelLen & 0xC0 != 0 { break } // compressed pointer
            offset += labelLen
        }
        // Skip QTYPE(2) + QCLASS(2)
        offset += 4
        guard offset <= queryData.count else { return nil }

        let questionEnd = offset

        // Determine RDATA length from QTYPE
        var rdLength: UInt16 = 0
        var ansType: UInt16 = 0
        if fakeIP != nil {
            if qtype == 1 {        // A
                rdLength = 4
                ansType = 1
            } else if qtype == 28 { // AAAA
                rdLength = 16
                ansType = 28
            }
        }

        if rdLength > 0, let ipBytes = fakeIP {
            // Answer response — build directly into Data (no intermediate [UInt8])
            let answerRecLen = 12 + Int(rdLength)
            let responseLen = questionEnd + answerRecLen

            var response = Data(count: responseLen)
            response.withUnsafeMutableBytes { ptr in
                guard let p = ptr.bindMemory(to: UInt8.self).baseAddress,
                      let src = queryData.baseAddress else { return }

                // Copy header + question section
                memcpy(p, src, questionEnd)

                // Response flags: QR=1, AA=1, RD=1, RA=1
                p[2] = 0x85; p[3] = 0x80
                // ANCOUNT = 1
                p[6] = 0x00; p[7] = 0x01
                // NSCOUNT = 0, ARCOUNT = 0
                p[8] = 0x00; p[9] = 0x00; p[10] = 0x00; p[11] = 0x00

                // Answer section
                let ans = questionEnd
                p[ans + 0] = 0xC0                              // Name pointer
                p[ans + 1] = 0x0C                              // to offset 12
                p[ans + 2] = UInt8(ansType >> 8)               // TYPE
                p[ans + 3] = UInt8(ansType & 0xFF)
                p[ans + 4] = 0x00; p[ans + 5] = 0x01          // CLASS = IN
                p[ans + 6] = 0x00; p[ans + 7] = 0x00          // TTL = 1 second
                p[ans + 8] = 0x00; p[ans + 9] = 0x01
                p[ans + 10] = UInt8(rdLength >> 8)             // RDLENGTH
                p[ans + 11] = UInt8(rdLength & 0xFF)

                // RDATA
                memcpy(p + ans + 12, ipBytes, Int(rdLength))
            }
            return response
        } else {
            // NODATA response (ANCOUNT=0) — build directly into Data
            var response = Data(count: questionEnd)
            response.withUnsafeMutableBytes { ptr in
                guard let p = ptr.bindMemory(to: UInt8.self).baseAddress,
                      let src = queryData.baseAddress else { return }
                memcpy(p, src, questionEnd)
                p[2] = 0x85; p[3] = 0x80
                p[6] = 0x00; p[7] = 0x00
                p[8] = 0x00; p[9] = 0x00; p[10] = 0x00; p[11] = 0x00
            }
            return response
        }
    }
}
