//
//  ngtcp2_bridge.h
//  Anywhere
//
//  Created by Argsment Limited on 4/10/26.
//

#ifndef NGTCP2_BRIDGE_H
#define NGTCP2_BRIDGE_H

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include "shared.h"
#include "ngtcp2_swift_bridge.h"

/* AEAD cipher type identifiers (must match ngtcp2_apple_aead_type enum) */
#define NGTCP2_APPLE_AEAD_AES_128_GCM         0
#define NGTCP2_APPLE_AEAD_AES_256_GCM         1
#define NGTCP2_APPLE_AEAD_CHACHA20_POLY1305   2

/* TLS cipher suite IDs for ngtcp2_crypto_ctx_tls */
#define NGTCP2_APPLE_CS_AES_128_GCM_SHA256       0x1301
#define NGTCP2_APPLE_CS_AES_256_GCM_SHA384       0x1302
#define NGTCP2_APPLE_CS_CHACHA20_POLY1305_SHA256 0x1303

/* Swift CryptoKit callback types for AEAD operations */
typedef int (*ngtcp2_apple_aead_encrypt_fn)(
    uint8_t *dest, const uint8_t *key, size_t keylen, const uint8_t *nonce,
    size_t noncelen, const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *aad, size_t aadlen, int aead_type);

typedef int (*ngtcp2_apple_aead_decrypt_fn)(
    uint8_t *dest, const uint8_t *key, size_t keylen, const uint8_t *nonce,
    size_t noncelen, const uint8_t *ciphertext, size_t ciphertextlen,
    const uint8_t *aad, size_t aadlen, int aead_type);

/* Register CryptoKit AEAD callbacks (must be called before any QUIC ops) */
void ngtcp2_crypto_apple_set_aead_callbacks(
    ngtcp2_apple_aead_encrypt_fn encrypt_fn,
    ngtcp2_apple_aead_decrypt_fn decrypt_fn);

#endif /* NGTCP2_BRIDGE_H */
