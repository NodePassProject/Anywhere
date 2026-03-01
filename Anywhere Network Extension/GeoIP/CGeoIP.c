//
//  CGeoIP.c
//  Network Extension
//
//  Binary search GeoIP lookup using direct pointer arithmetic.
//

#include "CGeoIP.h"
#include <arpa/inet.h>

uint16_t geoip_lookup(const uint8_t *db, size_t db_len, const char *ip_str) {
    if (!db || db_len < 8 || !ip_str) return 0;

    // Verify magic "GEO1"
    if (db[0] != 'G' || db[1] != 'E' || db[2] != 'O' || db[3] != '1') return 0;

    uint32_t count = (uint32_t)db[4] << 24 | (uint32_t)db[5] << 16 |
                     (uint32_t)db[6] << 8  | db[7];
    if (db_len < 8 + (size_t)count * 10) return 0;

    // Parse IPv4 string → host-order uint32
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) return 0;
    uint32_t ip = ntohl(addr.s_addr);

    // Binary search: find largest startIP <= ip
    const uint8_t *entries = db + 8;
    int lo = 0, hi = (int)count - 1, best = -1;

    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        const uint8_t *e = entries + mid * 10;
        uint32_t startIP = (uint32_t)e[0] << 24 | (uint32_t)e[1] << 16 |
                           (uint32_t)e[2] << 8  | e[3];
        if (startIP <= ip) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }

    if (best < 0) return 0;

    const uint8_t *e = entries + best * 10;
    uint32_t endIP = (uint32_t)e[4] << 24 | (uint32_t)e[5] << 16 |
                     (uint32_t)e[6] << 8  | e[7];
    if (ip > endIP) return 0;

    return (uint16_t)e[8] << 8 | e[9];
}
