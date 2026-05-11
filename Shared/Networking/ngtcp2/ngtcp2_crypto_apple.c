//
//  ngtcp2_crypto_apple.c
//  Anywhere
//
//  Created by Argsment Limited on 4/10/26.
//

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <ngtcp2/ngtcp2_crypto.h>

#include "ngtcp2_macro.h"
#include "shared.h"

#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCrypto.h>
#include <Security/SecRandom.h>

/* --- Cipher type identification --- */

typedef enum {
  NGTCP2_APPLE_CIPHER_AES_128,
  NGTCP2_APPLE_CIPHER_AES_256,
  NGTCP2_APPLE_CIPHER_CHACHA20,
} ngtcp2_apple_cipher_type;

typedef struct {
  ngtcp2_apple_cipher_type type;
} ngtcp2_apple_cipher;

static ngtcp2_apple_cipher cipher_aes_128 = {NGTCP2_APPLE_CIPHER_AES_128};
static ngtcp2_apple_cipher cipher_aes_256 = {NGTCP2_APPLE_CIPHER_AES_256};
static ngtcp2_apple_cipher cipher_chacha20 = {NGTCP2_APPLE_CIPHER_CHACHA20};

typedef enum {
  NGTCP2_APPLE_AEAD_AES_128_GCM,
  NGTCP2_APPLE_AEAD_AES_256_GCM,
  NGTCP2_APPLE_AEAD_CHACHA20_POLY1305,
} ngtcp2_apple_aead_type;

typedef struct {
  ngtcp2_apple_aead_type type;
} ngtcp2_apple_aead;

static ngtcp2_apple_aead aead_aes_128_gcm = {NGTCP2_APPLE_AEAD_AES_128_GCM};
static ngtcp2_apple_aead aead_aes_256_gcm = {NGTCP2_APPLE_AEAD_AES_256_GCM};
static ngtcp2_apple_aead aead_chacha20_poly1305 = {
    NGTCP2_APPLE_AEAD_CHACHA20_POLY1305};

typedef enum {
  NGTCP2_APPLE_MD_SHA256,
  NGTCP2_APPLE_MD_SHA384,
} ngtcp2_apple_md_type;

typedef struct {
  ngtcp2_apple_md_type type;
} ngtcp2_apple_md;

static ngtcp2_apple_md md_sha256 = {NGTCP2_APPLE_MD_SHA256};
static ngtcp2_apple_md md_sha384 = {NGTCP2_APPLE_MD_SHA384};

/* --- AEAD context (stores key + cipher type) --- */

typedef struct {
  ngtcp2_apple_aead_type type;
  uint8_t key[32]; /* max key size */
  size_t keylen;
} ngtcp2_apple_aead_ctx;

/* --- Cipher context (for header protection) --- */

typedef struct {
  ngtcp2_apple_cipher_type type;
  uint8_t key[32];
  size_t keylen;
} ngtcp2_apple_hp_ctx;

/* --- Swift CryptoKit callback function pointers ---
   These are set from Swift during initialization.
   They bridge the C crypto backend to Swift CryptoKit. */

typedef int (*ngtcp2_apple_aead_encrypt_fn)(
    uint8_t *dest, const uint8_t *key, size_t keylen, const uint8_t *nonce,
    size_t noncelen, const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *aad, size_t aadlen, int aead_type);

typedef int (*ngtcp2_apple_aead_decrypt_fn)(
    uint8_t *dest, const uint8_t *key, size_t keylen, const uint8_t *nonce,
    size_t noncelen, const uint8_t *ciphertext, size_t ciphertextlen,
    const uint8_t *aad, size_t aadlen, int aead_type);

static ngtcp2_apple_aead_encrypt_fn _aead_encrypt_fn = NULL;
static ngtcp2_apple_aead_decrypt_fn _aead_decrypt_fn = NULL;

void ngtcp2_crypto_apple_set_aead_callbacks(
    ngtcp2_apple_aead_encrypt_fn encrypt_fn,
    ngtcp2_apple_aead_decrypt_fn decrypt_fn) {
  _aead_encrypt_fn = encrypt_fn;
  _aead_decrypt_fn = decrypt_fn;
}

/* --- Basic initialization functions --- */

ngtcp2_crypto_aead *ngtcp2_crypto_aead_aes_128_gcm(ngtcp2_crypto_aead *aead) {
  return ngtcp2_crypto_aead_init(aead, (void *)&aead_aes_128_gcm);
}

ngtcp2_crypto_md *ngtcp2_crypto_md_sha256(ngtcp2_crypto_md *md) {
  md->native_handle = (void *)&md_sha256;
  return md;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx) {
  ngtcp2_crypto_aead_init(&ctx->aead, (void *)&aead_aes_128_gcm);
  ctx->md.native_handle = (void *)&md_sha256;
  ctx->hp.native_handle = (void *)&cipher_aes_128;
  ctx->max_encryption = 0;
  ctx->max_decryption_failure = 0;
  return ctx;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_init(ngtcp2_crypto_aead *aead,
                                            void *aead_native_handle) {
  aead->native_handle = aead_native_handle;
  aead->max_overhead = 16; /* All QUIC AEAD ciphers have 16-byte tag */
  return aead;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_retry(ngtcp2_crypto_aead *aead) {
  return ngtcp2_crypto_aead_init(aead, (void *)&aead_aes_128_gcm);
}

/* --- Size query functions --- */

size_t ngtcp2_crypto_md_hashlen(const ngtcp2_crypto_md *md) {
  ngtcp2_apple_md *m = (ngtcp2_apple_md *)md->native_handle;
  switch (m->type) {
  case NGTCP2_APPLE_MD_SHA256:
    return 32;
  case NGTCP2_APPLE_MD_SHA384:
    return 48;
  default:
    return 32;
  }
}

size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead) {
  ngtcp2_apple_aead *a = (ngtcp2_apple_aead *)aead->native_handle;
  switch (a->type) {
  case NGTCP2_APPLE_AEAD_AES_128_GCM:
    return 16;
  case NGTCP2_APPLE_AEAD_AES_256_GCM:
    return 32;
  case NGTCP2_APPLE_AEAD_CHACHA20_POLY1305:
    return 32;
  default:
    return 16;
  }
}

size_t ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead) {
  (void)aead;
  return 12; /* All QUIC AEAD ciphers use 12-byte nonce */
}

/* --- HKDF functions using CommonCrypto HMAC --- */

int ngtcp2_crypto_hkdf_extract(uint8_t *dest, const ngtcp2_crypto_md *md,
                               const uint8_t *secret, size_t secretlen,
                               const uint8_t *salt, size_t saltlen) {
  ngtcp2_apple_md *m = (ngtcp2_apple_md *)md->native_handle;
  CCHmacAlgorithm algo;

  switch (m->type) {
  case NGTCP2_APPLE_MD_SHA256:
    algo = kCCHmacAlgSHA256;
    break;
  case NGTCP2_APPLE_MD_SHA384:
    algo = kCCHmacAlgSHA384;
    break;
  default:
    return -1;
  }

  /* HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM) */
  CCHmac(algo, salt, saltlen, secret, secretlen, dest);
  return 0;
}

int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen,
                              const ngtcp2_crypto_md *md, const uint8_t *secret,
                              size_t secretlen, const uint8_t *info,
                              size_t infolen) {
  ngtcp2_apple_md *m = (ngtcp2_apple_md *)md->native_handle;
  CCHmacAlgorithm algo;
  size_t hashlen;
  uint8_t t[CC_SHA512_DIGEST_LENGTH]; /* max hash output */
  size_t t_len = 0;
  uint8_t counter = 1;
  size_t remaining = destlen;
  size_t to_copy;

  switch (m->type) {
  case NGTCP2_APPLE_MD_SHA256:
    algo = kCCHmacAlgSHA256;
    hashlen = CC_SHA256_DIGEST_LENGTH;
    break;
  case NGTCP2_APPLE_MD_SHA384:
    algo = kCCHmacAlgSHA384;
    hashlen = CC_SHA384_DIGEST_LENGTH;
    break;
  default:
    return -1;
  }

  /* HKDF-Expand: T(i) = HMAC-Hash(PRK, T(i-1) || info || i) */
  while (remaining > 0) {
    CCHmacContext hmac_ctx;
    CCHmacInit(&hmac_ctx, algo, secret, secretlen);
    if (t_len > 0) {
      CCHmacUpdate(&hmac_ctx, t, t_len);
    }
    CCHmacUpdate(&hmac_ctx, info, infolen);
    CCHmacUpdate(&hmac_ctx, &counter, 1);
    CCHmacFinal(&hmac_ctx, t);
    t_len = hashlen;

    to_copy = remaining < hashlen ? remaining : hashlen;
    memcpy(dest, t, to_copy);
    dest += to_copy;
    remaining -= to_copy;
    counter++;
  }

  return 0;
}

int ngtcp2_crypto_hkdf(uint8_t *dest, size_t destlen,
                       const ngtcp2_crypto_md *md, const uint8_t *secret,
                       size_t secretlen, const uint8_t *salt, size_t saltlen,
                       const uint8_t *info, size_t infolen) {
  uint8_t prk[CC_SHA512_DIGEST_LENGTH];

  if (ngtcp2_crypto_hkdf_extract(prk, md, secret, secretlen, salt, saltlen) !=
      0) {
    return -1;
  }

  return ngtcp2_crypto_hkdf_expand(dest, destlen, md, prk,
                                   ngtcp2_crypto_md_hashlen(md), info, infolen);
}

/* --- AEAD context management --- */

int ngtcp2_crypto_aead_ctx_encrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  ngtcp2_apple_aead *a = (ngtcp2_apple_aead *)aead->native_handle;
  ngtcp2_apple_aead_ctx *ctx;

  (void)noncelen;

  ctx = malloc(sizeof(*ctx));
  if (ctx == NULL) {
    return -1;
  }

  ctx->type = a->type;
  ctx->keylen = ngtcp2_crypto_aead_keylen(aead);
  memcpy(ctx->key, key, ctx->keylen);

  aead_ctx->native_handle = ctx;
  return 0;
}

int ngtcp2_crypto_aead_ctx_decrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  return ngtcp2_crypto_aead_ctx_encrypt_init(aead_ctx, aead, key, noncelen);
}

void ngtcp2_crypto_aead_ctx_free(ngtcp2_crypto_aead_ctx *aead_ctx) {
  if (aead_ctx->native_handle) {
    free(aead_ctx->native_handle);
  }
}

/* --- Cipher context management (for header protection) --- */

int ngtcp2_crypto_cipher_ctx_encrypt_init(ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                          const ngtcp2_crypto_cipher *cipher,
                                          const uint8_t *key) {
  ngtcp2_apple_cipher *c = (ngtcp2_apple_cipher *)cipher->native_handle;
  ngtcp2_apple_hp_ctx *ctx;

  ctx = malloc(sizeof(*ctx));
  if (ctx == NULL) {
    return -1;
  }

  ctx->type = c->type;
  switch (c->type) {
  case NGTCP2_APPLE_CIPHER_AES_128:
    ctx->keylen = 16;
    break;
  case NGTCP2_APPLE_CIPHER_AES_256:
  case NGTCP2_APPLE_CIPHER_CHACHA20:
    ctx->keylen = 32;
    break;
  }
  memcpy(ctx->key, key, ctx->keylen);

  cipher_ctx->native_handle = ctx;
  return 0;
}

void ngtcp2_crypto_cipher_ctx_free(ngtcp2_crypto_cipher_ctx *cipher_ctx) {
  if (!cipher_ctx->native_handle) {
    return;
  }
  free(cipher_ctx->native_handle);
}

/* --- Encrypt/Decrypt via Swift CryptoKit callbacks --- */

int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen) {
  ngtcp2_apple_aead_ctx *ctx = (ngtcp2_apple_aead_ctx *)aead_ctx->native_handle;

  (void)aead;

  if (!_aead_encrypt_fn) {
    return -1;
  }

  return _aead_encrypt_fn(dest, ctx->key, ctx->keylen, nonce, noncelen,
                          plaintext, plaintextlen, aad, aadlen, (int)ctx->type);
}

int ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen) {
  ngtcp2_apple_aead_ctx *ctx = (ngtcp2_apple_aead_ctx *)aead_ctx->native_handle;

  (void)aead;

  if (!_aead_decrypt_fn) {
    return -1;
  }

  return _aead_decrypt_fn(dest, ctx->key, ctx->keylen, nonce, noncelen,
                          ciphertext, ciphertextlen, aad, aadlen,
                          (int)ctx->type);
}

/* --- Header Protection mask ---
   AES-ECB is available in CommonCrypto's public API. */

int ngtcp2_crypto_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                          const ngtcp2_crypto_cipher_ctx *hp_ctx,
                          const uint8_t *sample) {
  ngtcp2_apple_hp_ctx *ctx = (ngtcp2_apple_hp_ctx *)hp_ctx->native_handle;

  (void)hp;

  switch (ctx->type) {
  case NGTCP2_APPLE_CIPHER_AES_128:
  case NGTCP2_APPLE_CIPHER_AES_256: {
    /* AES-ECB encrypt single 16-byte block */
    size_t outlen = 0;
    CCCryptorStatus status =
        CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode, ctx->key,
                ctx->keylen, NULL, sample, 16, dest, 16, &outlen);
    return status == kCCSuccess ? 0 : -1;
  }
  case NGTCP2_APPLE_CIPHER_CHACHA20:
    /* ChaCha20 HP: counter from sample[0..3], nonce from sample[4..15],
       encrypt 5 zero bytes. Handled via Swift callback if needed. */
    return -1;
  default:
    return -1;
  }
}

/* Note: _cb callback wrappers (ngtcp2_crypto_encrypt_cb, decrypt_cb,
   hp_mask_cb) are defined in shared.c and call our encrypt/decrypt/hp_mask
   functions above. No need to duplicate them here. */

/* --- Random --- */

int ngtcp2_crypto_random(uint8_t *data, size_t datalen) {
  if (SecRandomCopyBytes(kSecRandomDefault, datalen, data) != errSecSuccess) {
    return -1;
  }
  return 0;
}

/* Note: delete_crypto_*_ctx_cb are defined in shared.c.
   Path challenge callbacks need our random implementation. */

int ngtcp2_crypto_get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data,
                                             void *user_data) {
  (void)conn;
  (void)user_data;
  if (SecRandomCopyBytes(kSecRandomDefault, NGTCP2_PATH_CHALLENGE_DATALEN,
                         data) != errSecSuccess) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int ngtcp2_crypto_get_path_challenge_data2_cb(ngtcp2_conn *conn,
                                              ngtcp2_path_challenge_data *data,
                                              void *user_data) {
  (void)conn;
  (void)user_data;
  if (SecRandomCopyBytes(kSecRandomDefault, NGTCP2_PATH_CHALLENGE_DATALEN,
                         data->data) != errSecSuccess) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

/* --- TLS integration ---
   We handle TLS in Swift, so these are minimal implementations.
   The Swift layer calls ngtcp2_conn_install_*_key and
   ngtcp2_conn_submit_crypto_data directly. */

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx,
                                         void *tls_native_handle) {
  /* tls_native_handle encodes cipher suite as uintptr_t from Swift */
  if (!tls_native_handle) {
    return NULL;
  }

  uintptr_t cs = (uintptr_t)tls_native_handle;
  switch (cs) {
  case 0x1301: /* TLS_AES_128_GCM_SHA256 */
    ngtcp2_crypto_aead_init(&ctx->aead, (void *)&aead_aes_128_gcm);
    ctx->md.native_handle = (void *)&md_sha256;
    ctx->hp.native_handle = (void *)&cipher_aes_128;
    ctx->max_encryption = NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_GCM;
    ctx->max_decryption_failure = NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_GCM;
    break;
  case 0x1302: /* TLS_AES_256_GCM_SHA384 */
    ngtcp2_crypto_aead_init(&ctx->aead, (void *)&aead_aes_256_gcm);
    ctx->md.native_handle = (void *)&md_sha384;
    ctx->hp.native_handle = (void *)&cipher_aes_256;
    ctx->max_encryption = NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_GCM;
    ctx->max_decryption_failure = NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_GCM;
    break;
  case 0x1303: /* TLS_CHACHA20_POLY1305_SHA256 */
    ngtcp2_crypto_aead_init(&ctx->aead, (void *)&aead_chacha20_poly1305);
    ctx->md.native_handle = (void *)&md_sha256;
    ctx->hp.native_handle = (void *)&cipher_chacha20;
    ctx->max_encryption = NGTCP2_CRYPTO_MAX_ENCRYPTION_CHACHA20_POLY1305;
    ctx->max_decryption_failure =
        NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_CHACHA20_POLY1305;
    break;
  default:
    return NULL;
  }
  return ctx;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls_early(ngtcp2_crypto_ctx *ctx,
                                               void *tls_native_handle) {
  return ngtcp2_crypto_ctx_tls(ctx, tls_native_handle);
}

int ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn *conn, void *tls) {
  (void)conn;
  (void)tls;
  return 0;
}

int ngtcp2_crypto_set_local_transport_params(void *tls, const uint8_t *buf,
                                             size_t len) {
  (void)tls;
  (void)buf;
  (void)len;
  return 0;
}

/* --- TLS handshake data processing stub --- */

int ngtcp2_crypto_read_write_crypto_data(
    ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level,
    const uint8_t *data, size_t datalen) {
  (void)conn;
  (void)encryption_level;
  (void)data;
  (void)datalen;
  /* Not used - TLS handled in Swift */
  return -1;
}

/* Note: ngtcp2_crypto_version_negotiation_cb is defined in shared.c */
