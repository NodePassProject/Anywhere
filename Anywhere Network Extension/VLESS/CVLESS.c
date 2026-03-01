//
//  CVLESS.c
//  Network Extension
//
//  Created by Argsment Limited on 1/23/26.
//

#include "CVLESS.h"
#include <string.h>
#include <stdlib.h>

size_t build_vless_request_header(uint8_t *buffer,
                                  const uint8_t *uuid,
                                  uint8_t command,
                                  uint16_t port,
                                  uint8_t addressType,
                                  const uint8_t *address,
                                  size_t addressLen) {
    size_t offset = 0;
    
    // Version (1 byte) - always 0
    buffer[offset++] = 0x00;
    
    // UUID (16 bytes)
    memcpy(buffer + offset, uuid, 16);
    offset += 16;
    
    // Addons length (1 byte) - 0 for no addons
    buffer[offset++] = 0x00;
    
    // Command (1 byte)
    buffer[offset++] = command;
    
    // Port (2 bytes, big-endian)
    buffer[offset++] = (uint8_t)(port >> 8);
    buffer[offset++] = (uint8_t)(port & 0xFF);
    
    // Address type (1 byte)
    buffer[offset++] = addressType;
    
    // Address data
    if (addressType == VLESS_ADDR_DOMAIN) {
        // Domain: length byte + domain string
        buffer[offset++] = (uint8_t)addressLen;
        memcpy(buffer + offset, address, addressLen);
        offset += addressLen;
    } else if (addressType == VLESS_ADDR_IPV4) {
        // IPv4: 4 bytes
        memcpy(buffer + offset, address, 4);
        offset += 4;
    } else if (addressType == VLESS_ADDR_IPV6) {
        // IPv6: 16 bytes
        memcpy(buffer + offset, address, 16);
        offset += 16;
    }
    
    return offset;
}

int parse_ipv4_address(const char *str, size_t strLen, uint8_t *outBytes) {
    if (strLen == 0 || strLen > 15) return 0;  // Max "255.255.255.255"
    
    // Copy to null-terminated buffer for parsing
    char buf[16];
    memcpy(buf, str, strLen);
    buf[strLen] = '\0';
    
    int parts[4];
    int count = 0;
    char *ptr = buf;
    char *end;
    
    while (count < 4) {
        long val = strtol(ptr, &end, 10);
        if (val < 0 || val > 255) return 0;
        if (ptr == end) return 0;  // No digits parsed
        
        parts[count++] = (int)val;
        
        if (*end == '\0') break;
        if (*end != '.') return 0;
        ptr = end + 1;
    }
    
    if (count != 4) return 0;
    
    outBytes[0] = (uint8_t)parts[0];
    outBytes[1] = (uint8_t)parts[1];
    outBytes[2] = (uint8_t)parts[2];
    outBytes[3] = (uint8_t)parts[3];
    
    return 1;
}

int parse_ipv6_address(const char *str, size_t strLen, uint8_t *outBytes) {
    if (strLen == 0 || strLen > 45) return 0;  // Max with brackets
    
    // Copy to buffer, strip brackets if present
    char buf[46];
    size_t start = 0;
    size_t len = strLen;
    
    if (strLen >= 2 && str[0] == '[' && str[strLen - 1] == ']') {
        start = 1;
        len = strLen - 2;
    }
    
    if (len == 0 || len > 39) return 0;
    memcpy(buf, str + start, len);
    buf[len] = '\0';
    
    // Parse IPv6 - handle :: expansion
    uint16_t parts[8] = {0};
    int partCount = 0;
    int doubleColonPos = -1;
    
    char *ptr = buf;
    while (*ptr && partCount < 8) {
        if (*ptr == ':') {
            if (*(ptr + 1) == ':') {
                if (doubleColonPos >= 0) return 0;  // Multiple ::
                doubleColonPos = partCount;
                ptr += 2;
                if (*ptr == '\0') break;
                continue;
            }
            ptr++;
            continue;
        }
        
        char *end;
        long val = strtol(ptr, &end, 16);
        if (val < 0 || val > 0xFFFF) return 0;
        if (ptr == end) return 0;
        
        parts[partCount++] = (uint16_t)val;
        ptr = end;
    }
    
    // Expand :: if present
    if (doubleColonPos >= 0) {
        int missing = 8 - partCount;
        if (missing < 0) return 0;
        
        // Shift parts after :: to the end
        for (int i = 7; i >= doubleColonPos + missing; i--) {
            parts[i] = parts[i - missing];
        }
        // Zero the expanded section
        for (int i = doubleColonPos; i < doubleColonPos + missing; i++) {
            parts[i] = 0;
        }
    } else if (partCount != 8) {
        return 0;
    }
    
    // Convert to bytes (big-endian)
    for (int i = 0; i < 8; i++) {
        outBytes[i * 2] = (uint8_t)(parts[i] >> 8);
        outBytes[i * 2 + 1] = (uint8_t)(parts[i] & 0xFF);
    }
    
    return 1;
}

int parse_vless_address(const char *str, size_t strLen,
                        uint8_t *outType, uint8_t *outBytes, size_t *outLen) {
    // Try IPv4 first
    if (parse_ipv4_address(str, strLen, outBytes)) {
        *outType = VLESS_ADDR_IPV4;
        *outLen = 4;
        return 1;
    }
    
    // Try IPv6
    if (parse_ipv6_address(str, strLen, outBytes)) {
        *outType = VLESS_ADDR_IPV6;
        *outLen = 16;
        return 1;
    }
    
    // Treat as domain
    if (strLen > 255) return 0;  // Domain too long
    
    *outType = VLESS_ADDR_DOMAIN;
    memcpy(outBytes, str, strLen);
    *outLen = strLen;
    return 1;
}
