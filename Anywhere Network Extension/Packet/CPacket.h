//
//  CPacket.h
//  Network Extension
//
//  TLS processing utilities (used by Reality/Vision).
//

#ifndef CPacket_h
#define CPacket_h

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

// MARK: - TLS Utility Functions

/// XOR nonce with sequence number for TLS 1.3 (in-place)
/// @param nonce 12-byte nonce buffer (modified in place)
/// @param seqNum 64-bit sequence number
void xor_nonce_with_seq(uint8_t *nonce, uint64_t seqNum);

/// Copy payload to packet buffer
/// @param dst Destination buffer
/// @param src Source data
/// @param length Number of bytes to copy
void copy_payload(uint8_t *dst, const uint8_t *src, size_t length);

/// Parse TLS record header from buffer
/// @param buffer Input buffer
/// @param bufferLen Buffer length
/// @param outContentType Output: content type (0x17 = app data, 0x15 = alert)
/// @param outRecordLen Output: record body length
/// @return 1 if header parsed successfully, 0 if need more data
int parse_tls_header(const uint8_t *buffer, size_t bufferLen,
                     uint8_t *outContentType, uint16_t *outRecordLen);

/// Find content end in TLS 1.3 decrypted inner plaintext
/// TLS 1.3 format: [content][content_type][padding zeros]
/// @param data Decrypted data
/// @param length Data length
/// @param outContentType Output: inner content type byte
/// @return Index of last content byte (before content type), or -1 if invalid
ssize_t find_tls13_content_end(const uint8_t *data, size_t length, uint8_t *outContentType);

/// Strip TLS 1.3 padding and content type, return content length
/// @param data Decrypted data (will NOT be modified)
/// @param length Data length
/// @param outContentType Output: inner content type (0x17 = app data, 0x16 = handshake)
/// @return Content length (excluding type and padding), or -1 if invalid
ssize_t tls13_unwrap_content(const uint8_t *data, size_t length, uint8_t *outContentType);

// MARK: - UDP Length Framing

/// Write a 2-byte big-endian length prefix followed by the payload.
/// @param out Caller buffer, must be >= 2 + len bytes
/// @param payload UDP payload data
/// @param len Payload length
void frame_udp_payload(uint8_t *out, const uint8_t *payload, uint16_t len);

// MARK: - DNS Query Parsing

/// Parse a DNS query to extract the queried domain name.
/// @param data Raw DNS payload (UDP body)
/// @param len Payload length
/// @param outDomain Caller buffer for the null-terminated domain string
/// @param outDomainLen In: buffer capacity; out: domain string length (excluding null terminator)
/// @return 1 on success, 0 on failure
int parse_dns_query(const uint8_t *data, size_t len,
                    char *outDomain, size_t *outDomainLen);

/// Extended DNS query parser that also extracts the QTYPE.
/// @param data Raw DNS payload (UDP body)
/// @param len Payload length
/// @param outDomain Caller buffer for the null-terminated domain string
/// @param outDomainLen In: buffer capacity; out: domain string length (excluding null terminator)
/// @param outQType Output: query type (1=A, 28=AAAA, etc.)
/// @return 1 on success, 0 on failure
int parse_dns_query_ext(const uint8_t *data, size_t len,
                        char *outDomain, size_t *outDomainLen,
                        uint16_t *outQType);

/// Generate a minimal DNS response for a query.
/// For QTYPE=A (1):    if fakeIP is non-NULL, returns A record (RDLENGTH=4, TTL=1).
/// For QTYPE=AAAA (28): if fakeIP is non-NULL, returns AAAA record (RDLENGTH=16, TTL=1).
/// If fakeIP is NULL or QTYPE is neither A nor AAAA: returns NODATA (ANCOUNT=0).
/// @param queryData Original DNS query payload
/// @param queryLen Query payload length
/// @param fakeIP Fake IP address bytes (4 for A, 16 for AAAA), or NULL for NODATA
/// @param qtype The query type from parse_dns_query_ext
/// @param outBuf Output buffer for the DNS response
/// @param outBufSize Output buffer capacity
/// @return Response length on success, 0 on failure
int generate_dns_response(const uint8_t *queryData, size_t queryLen,
                          const uint8_t *fakeIP, uint16_t qtype,
                          uint8_t *outBuf, size_t outBufSize);

// MARK: - TLS ServerHello Parsing

/// Parse a TLS ServerHello to extract the X25519 key share and cipher suite.
/// @param data Raw TLS data (may contain multiple records)
/// @param len Data length
/// @param outKeyShare Caller buffer for the 32-byte X25519 key share
/// @param outCipherSuite Output: TLS cipher suite identifier
/// @return 1 on success, 0 if parsing fails or key_share not found
int parse_server_hello(const uint8_t *data, size_t len,
                       uint8_t *outKeyShare,
                       uint16_t *outCipherSuite);

#endif /* CPacket_h */
