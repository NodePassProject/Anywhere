//
//  CTLSKeyDerivation.h
//  Network Extension
//
//  TLS 1.3 key derivation using CommonCrypto (RFC 8446).
//

#ifndef CTLSKeyDerivation_h
#define CTLSKeyDerivation_h

#include <stdint.h>
#include <stddef.h>

// Cipher suite constants
#define TLS_AES_128_GCM_SHA256 0x1301
#define TLS_AES_256_GCM_SHA384 0x1302

/// Derive TLS 1.3 handshake keys from ECDH shared secret + transcript.
/// @param cipher_suite 0x1301 (AES-128-GCM) or 0x1302 (AES-256-GCM)
/// @param shared_secret ECDH shared secret
/// @param ss_len Shared secret length
/// @param transcript ClientHello + ServerHello concatenation
/// @param transcript_len Transcript length
/// @param out_hs_secret Output: handshake secret (hashLen bytes: 32 or 48)
/// @param out_client_key Output: client handshake key (keyLen bytes: 16 or 32)
/// @param out_client_iv Output: client handshake IV (12 bytes)
/// @param out_server_key Output: server handshake key (keyLen bytes: 16 or 32)
/// @param out_server_iv Output: server handshake IV (12 bytes)
/// @param out_client_traffic_secret Output: client handshake traffic secret (hashLen bytes)
/// @return 0 on success, -1 on error
int tls13_derive_handshake_keys(
    uint16_t cipher_suite,
    const uint8_t *shared_secret, size_t ss_len,
    const uint8_t *transcript, size_t transcript_len,
    uint8_t *out_hs_secret,
    uint8_t *out_client_key,
    uint8_t *out_client_iv,
    uint8_t *out_server_key,
    uint8_t *out_server_iv,
    uint8_t *out_client_traffic_secret);

/// Derive TLS 1.3 application keys from handshake secret + full transcript.
/// @param cipher_suite 0x1301 or 0x1302
/// @param hs_secret Handshake secret (from tls13_derive_handshake_keys)
/// @param hs_len Handshake secret length (hashLen)
/// @param transcript Full transcript (through server Finished)
/// @param transcript_len Transcript length
/// @param out_client_key Output: client application key (keyLen bytes)
/// @param out_client_iv Output: client application IV (12 bytes)
/// @param out_server_key Output: server application key (keyLen bytes)
/// @param out_server_iv Output: server application IV (12 bytes)
/// @return 0 on success, -1 on error
int tls13_derive_application_keys(
    uint16_t cipher_suite,
    const uint8_t *hs_secret, size_t hs_len,
    const uint8_t *transcript, size_t transcript_len,
    uint8_t *out_client_key,
    uint8_t *out_client_iv,
    uint8_t *out_server_key,
    uint8_t *out_server_iv);

/// Compute Client Finished verify_data.
/// @param cipher_suite 0x1301 or 0x1302
/// @param client_traffic_secret Client handshake traffic secret (hashLen bytes)
/// @param secret_len Secret length (hashLen)
/// @param transcript Handshake transcript (through server Finished)
/// @param transcript_len Transcript length
/// @param out_verify_data Output: verify data (hashLen bytes)
/// @return 0 on success, -1 on error
int tls13_compute_finished(
    uint16_t cipher_suite,
    const uint8_t *client_traffic_secret, size_t secret_len,
    const uint8_t *transcript, size_t transcript_len,
    uint8_t *out_verify_data);

/// Compute transcript hash.
/// @param cipher_suite 0x1301 or 0x1302
/// @param messages Concatenated handshake messages
/// @param messages_len Messages length
/// @param out_hash Output: hash (hashLen bytes: 32 or 48)
/// @return 0 on success, -1 on error
int tls13_transcript_hash(
    uint16_t cipher_suite,
    const uint8_t *messages, size_t messages_len,
    uint8_t *out_hash);

#endif /* CTLSKeyDerivation_h */
