//
//  CPacket.c
//  Network Extension
//
//  TLS processing utilities (used by Reality/Vision).
//

#include "CPacket.h"
#include <string.h>

// MARK: - TLS Utility Functions

void xor_nonce_with_seq(uint8_t *nonce, uint64_t seqNum) {
    // XOR last 8 bytes of nonce with sequence number (big-endian)
    nonce[4]  ^= (uint8_t)(seqNum >> 56);
    nonce[5]  ^= (uint8_t)(seqNum >> 48);
    nonce[6]  ^= (uint8_t)(seqNum >> 40);
    nonce[7]  ^= (uint8_t)(seqNum >> 32);
    nonce[8]  ^= (uint8_t)(seqNum >> 24);
    nonce[9]  ^= (uint8_t)(seqNum >> 16);
    nonce[10] ^= (uint8_t)(seqNum >> 8);
    nonce[11] ^= (uint8_t)(seqNum);
}

void copy_payload(uint8_t *dst, const uint8_t *src, size_t length) {
    memcpy(dst, src, length);
}

int parse_tls_header(const uint8_t *buffer, size_t bufferLen,
                     uint8_t *outContentType, uint16_t *outRecordLen) {
    if (bufferLen < 5) {
        return 0;
    }
    *outContentType = buffer[0];
    *outRecordLen = ((uint16_t)buffer[3] << 8) | buffer[4];
    return 1;
}

ssize_t find_tls13_content_end(const uint8_t *data, size_t length, uint8_t *outContentType) {
    if (length == 0) {
        return -1;
    }

    // Scan backwards to find last non-zero byte (content type)
    ssize_t i = (ssize_t)length - 1;

    // Fast path: check last byte (common case: no padding or minimal padding)
    if (length >= 8) {
        const uint8_t *end = data + length;
        if (end[-1] != 0) {
            *outContentType = end[-1];
            return (ssize_t)length - 1;
        }
    }

    // Scan backwards for non-zero
    while (i >= 0 && data[i] == 0) {
        i--;
    }

    if (i < 0) {
        return -1;  // All zeros, invalid
    }

    *outContentType = data[i];
    return i;
}

ssize_t tls13_unwrap_content(const uint8_t *data, size_t length, uint8_t *outContentType) {
    if (length == 0) {
        return -1;
    }

    ssize_t contentEnd = find_tls13_content_end(data, length, outContentType);
    if (contentEnd < 0) {
        return -1;
    }

    // contentEnd points to the content type byte, return length before it
    return contentEnd;
}

// MARK: - UDP Length Framing

void frame_udp_payload(uint8_t *out, const uint8_t *payload, uint16_t len) {
    out[0] = (uint8_t)(len >> 8);
    out[1] = (uint8_t)(len & 0xFF);
    memcpy(out + 2, payload, len);
}

// MARK: - DNS Query Parsing

int parse_dns_query_ext(const uint8_t *data, size_t len,
                        char *outDomain, size_t *outDomainLen,
                        uint16_t *outQType)
{
    // DNS header is 12 bytes: ID(2) Flags(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
    if (len < 12 || *outDomainLen == 0) {
        return 0;
    }

    // Check QDCOUNT >= 1 (bytes 4-5, big-endian)
    uint16_t qdcount = ((uint16_t)data[4] << 8) | data[5];
    if (qdcount == 0) {
        return 0;
    }

    // Parse QNAME starting at byte 12
    // Format: sequence of length-prefixed labels, terminated by zero-length label
    size_t offset = 12;
    size_t domainPos = 0;
    size_t capacity = *outDomainLen - 1;  // reserve space for null terminator

    while (offset < len) {
        uint8_t labelLen = data[offset];
        offset++;

        if (labelLen == 0) {
            // End of QNAME
            break;
        }

        // Compressed pointers not expected in queries, reject
        if ((labelLen & 0xC0) != 0) {
            return 0;
        }

        if (offset + labelLen > len) {
            return 0;
        }

        // Add dot separator between labels
        if (domainPos > 0) {
            if (domainPos >= capacity) return 0;
            outDomain[domainPos++] = '.';
        }

        // Copy label
        if (domainPos + labelLen > capacity) {
            return 0;
        }
        memcpy(outDomain + domainPos, data + offset, labelLen);
        domainPos += labelLen;
        offset += labelLen;
    }

    if (domainPos == 0) {
        return 0;
    }

    outDomain[domainPos] = '\0';
    *outDomainLen = domainPos;

    // Read QTYPE: 2 bytes immediately after the zero-terminator of QNAME
    if (offset + 2 > len) {
        return 0;
    }
    *outQType = ((uint16_t)data[offset] << 8) | data[offset + 1];

    return 1;
}

int parse_dns_query(const uint8_t *data, size_t len,
                    char *outDomain, size_t *outDomainLen)
{
    uint16_t qtype;
    return parse_dns_query_ext(data, len, outDomain, outDomainLen, &qtype);
}

int generate_dns_response(const uint8_t *queryData, size_t queryLen,
                          const uint8_t *fakeIP, uint16_t qtype,
                          uint8_t *outBuf, size_t outBufSize)
{
    // Need at least a DNS header (12 bytes)
    if (queryLen < 12) {
        return 0;
    }

    // Find the end of the question section:
    // Skip QNAME (sequence of labels terminated by zero), then QTYPE(2) + QCLASS(2)
    size_t offset = 12;
    while (offset < queryLen) {
        uint8_t labelLen = queryData[offset];
        offset++;
        if (labelLen == 0) break;
        if ((labelLen & 0xC0) != 0) {
            // Compressed pointer: 2 bytes total
            break;
        }
        offset += labelLen;
    }
    // Skip QTYPE(2) + QCLASS(2)
    offset += 4;
    if (offset > queryLen) {
        return 0;
    }

    size_t questionEnd = offset;

    // Determine RDATA length from QTYPE
    uint16_t rdLength = 0;
    uint16_t ansType = 0;
    if (fakeIP != NULL) {
        if (qtype == 1) {        // A
            rdLength = 4;
            ansType = 1;
        } else if (qtype == 28) { // AAAA
            rdLength = 16;
            ansType = 28;
        }
    }

    if (rdLength > 0) {
        // Answer response: header + question + answer record (12 + rdLength)
        size_t answerRecLen = 12 + rdLength;  // name(2) + type(2) + class(2) + ttl(4) + rdlen(2) + rdata
        size_t responseLen = questionEnd + answerRecLen;
        if (outBufSize < responseLen) {
            return 0;
        }

        // Copy header + question section
        memcpy(outBuf, queryData, questionEnd);

        // Set response flags: QR=1, AA=1, RD=1, RA=1 (0x8580)
        // Matches Xray-core dns.go: Response + Authoritative + RecursionDesired + RecursionAvailable
        outBuf[2] = 0x85;
        outBuf[3] = 0x80;

        // ANCOUNT = 1
        outBuf[6] = 0x00;
        outBuf[7] = 0x01;

        // NSCOUNT = 0, ARCOUNT = 0
        outBuf[8] = 0x00;
        outBuf[9] = 0x00;
        outBuf[10] = 0x00;
        outBuf[11] = 0x00;

        // Answer section
        size_t ans = questionEnd;
        outBuf[ans + 0] = 0xC0;                       // Name pointer
        outBuf[ans + 1] = 0x0C;                       // to offset 12 (QNAME)
        outBuf[ans + 2] = (uint8_t)(ansType >> 8);    // TYPE
        outBuf[ans + 3] = (uint8_t)(ansType & 0xFF);
        outBuf[ans + 4] = 0x00;                        // CLASS = IN
        outBuf[ans + 5] = 0x01;
        outBuf[ans + 6] = 0x00;                        // TTL = 1 second (matches Xray-core)
        outBuf[ans + 7] = 0x00;
        outBuf[ans + 8] = 0x00;
        outBuf[ans + 9] = 0x01;
        outBuf[ans + 10] = (uint8_t)(rdLength >> 8);  // RDLENGTH
        outBuf[ans + 11] = (uint8_t)(rdLength & 0xFF);
        memcpy(outBuf + ans + 12, fakeIP, rdLength);   // RDATA

        return (int)responseLen;
    } else {
        // NODATA response (ANCOUNT=0)
        if (outBufSize < questionEnd) {
            return 0;
        }

        // Copy header + question section
        memcpy(outBuf, queryData, questionEnd);

        // Set response flags: QR=1, AA=1, RD=1, RA=1 (0x8580)
        outBuf[2] = 0x85;
        outBuf[3] = 0x80;

        // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
        outBuf[6] = 0x00;
        outBuf[7] = 0x00;
        outBuf[8] = 0x00;
        outBuf[9] = 0x00;
        outBuf[10] = 0x00;
        outBuf[11] = 0x00;

        return (int)questionEnd;
    }
}

// MARK: - TLS ServerHello Parsing

int parse_server_hello(const uint8_t *data, size_t len,
                       uint8_t *outKeyShare,
                       uint16_t *outCipherSuite)
{
    size_t offset = 0;

    while (offset + 5 < len) {
        uint8_t contentType = data[offset];
        if (contentType != 0x16) break;

        uint16_t recordLen = ((uint16_t)data[offset + 3] << 8) | data[offset + 4];
        offset += 5;

        if (offset + recordLen > len) break;
        if (data[offset] != 0x02) { // Not ServerHello
            offset += recordLen;
            continue;
        }

        // Skip handshake type (1) + length (3) + version (2) + random (32) = 38
        size_t shOffset = offset + 1 + 3 + 2 + 32;
        if (shOffset >= len) return 0;

        // Session ID
        uint8_t sessionIdLen = data[shOffset];
        shOffset += 1 + sessionIdLen;

        // Cipher suite (2 bytes)
        if (shOffset + 2 > len) return 0;
        *outCipherSuite = ((uint16_t)data[shOffset] << 8) | data[shOffset + 1];

        // Skip cipher suite (2) + compression (1)
        shOffset += 3;

        if (shOffset + 2 > len) return 0;

        // Extensions length
        uint16_t extLen = ((uint16_t)data[shOffset] << 8) | data[shOffset + 1];
        shOffset += 2;

        size_t extEnd = shOffset + extLen;
        if (extEnd > len) return 0;

        // Walk extensions looking for key_share (0x0033)
        while (shOffset + 4 <= extEnd) {
            uint16_t extType = ((uint16_t)data[shOffset] << 8) | data[shOffset + 1];
            uint16_t extDataLen = ((uint16_t)data[shOffset + 2] << 8) | data[shOffset + 3];
            shOffset += 4;

            if (extType == 0x0033) {
                if (shOffset + 4 > len) return 0;
                uint16_t group = ((uint16_t)data[shOffset] << 8) | data[shOffset + 1];
                uint16_t keyLen = ((uint16_t)data[shOffset + 2] << 8) | data[shOffset + 3];
                shOffset += 4;

                if (group == 0x001d && keyLen == 32) {
                    if (shOffset + 32 > len) return 0;
                    memcpy(outKeyShare, data + shOffset, 32);
                    return 1;
                }
            }

            shOffset += extDataLen;
        }

        break;
    }

    return 0;
}

