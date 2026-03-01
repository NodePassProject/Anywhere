//
//  CGeoIP.h
//  Network Extension
//
//  Binary search GeoIP lookup using direct pointer arithmetic.
//

#ifndef CGeoIP_h
#define CGeoIP_h

#include <stdint.h>
#include <stddef.h>

/// Look up the country code for an IPv4 address string in the GeoIP database.
///
/// Parses the IPv4 string, then binary-searches the database entries.
/// Database format: "GEO1" magic (4B) + count (U32 BE) + entries[count],
/// each entry = startIP (U32 BE) + endIP (U32 BE) + countryCode (U16 BE).
///
/// @param db Pointer to the raw geoip.dat contents
/// @param db_len Length of the database in bytes
/// @param ip_str Null-terminated IPv4 dotted-quad string (e.g. "1.2.3.4")
/// @return Packed UInt16 country code (e.g. 0x434E for "CN"), or 0 if not found
uint16_t geoip_lookup(const uint8_t *db, size_t db_len, const char *ip_str);

#endif /* CGeoIP_h */
