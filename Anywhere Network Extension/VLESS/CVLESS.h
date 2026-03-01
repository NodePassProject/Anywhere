//
//  CVLESS.h
//  Network Extension
//
//  Created by Argsment Limited on 1/23/26.
//

#ifndef CVLESS_h
#define CVLESS_h

#include <stdint.h>
#include <stddef.h>

/// VLESS command types
#define VLESS_CMD_TCP 0x01
#define VLESS_CMD_UDP 0x02

/// VLESS address types
#define VLESS_ADDR_IPV4   0x01
#define VLESS_ADDR_DOMAIN 0x02
#define VLESS_ADDR_IPV6   0x03

/// Build VLESS request header
/// @param buffer Output buffer (must be at least 22 + addressLen bytes)
/// @param uuid 16-byte UUID
/// @param command VLESS_CMD_TCP or VLESS_CMD_UDP
/// @param port Destination port (host byte order)
/// @param addressType VLESS_ADDR_IPV4, VLESS_ADDR_DOMAIN, or VLESS_ADDR_IPV6
/// @param address Address bytes (4 for IPv4, 16 for IPv6, or domain string)
/// @param addressLen Length of address data
/// @return Total header length written to buffer
size_t build_vless_request_header(uint8_t *buffer,
                                   const uint8_t *uuid,
                                   uint8_t command,
                                   uint16_t port,
                                   uint8_t addressType,
                                   const uint8_t *address,
                                   size_t addressLen);

/// Parse IPv4 address string to bytes
/// @param str IPv4 address string (e.g., "192.168.1.1")
/// @param strLen Length of string
/// @param outBytes Output buffer (4 bytes)
/// @return 1 on success, 0 on failure
int parse_ipv4_address(const char *str, size_t strLen, uint8_t *outBytes);

/// Parse IPv6 address string to bytes
/// @param str IPv6 address string (e.g., "2001:db8::1" or "[2001:db8::1]")
/// @param strLen Length of string
/// @param outBytes Output buffer (16 bytes)
/// @return 1 on success, 0 on failure
int parse_ipv6_address(const char *str, size_t strLen, uint8_t *outBytes);

/// Determine address type and parse address
/// @param str Address string (IPv4, IPv6, or domain)
/// @param strLen Length of string
/// @param outType Output: address type (VLESS_ADDR_*)
/// @param outBytes Output buffer (max 255 bytes for domain)
/// @param outLen Output: length of address bytes
/// @return 1 on success, 0 on failure
int parse_vless_address(const char *str, size_t strLen,
                        uint8_t *outType, uint8_t *outBytes, size_t *outLen);

#endif /* CVLESS_h */
