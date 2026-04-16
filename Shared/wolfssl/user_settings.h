/* user_settings.h — wolfSSL configuration for Anywhere
 *
 * Activated by -DWOLFSSL_USER_SETTINGS in the target build settings.
 * Scope: TLS 1.3 + QUIC client only. AES-GCM, ChaCha20-Poly1305, X25519, P-256.
 */

#ifndef ANYWHERE_WOLFSSL_USER_SETTINGS_H
#define ANYWHERE_WOLFSSL_USER_SETTINGS_H

#if defined(__APPLE__)
#  include <TargetConditionals.h>
#  if TARGET_OS_IPHONE
#    define IPHONE
#  endif
#endif

/* Route wc_GenerateSeed through SecRandomCopyBytes (anywhere_wolfssl_seed.c).
 * Avoids /dev/urandom, which is not consistently available inside the Network
 * Extension sandbox and otherwise triggers WC_INIT_E during wolfSSL_Init. */
#ifdef __cplusplus
extern "C" {
#endif
int anywhere_wolfssl_seed(unsigned char *output, unsigned int sz);
#ifdef __cplusplus
}
#endif
#define CUSTOM_RAND_GENERATE_SEED anywhere_wolfssl_seed

/* Sizes */
#define SIZEOF_LONG_LONG 8
#define HAVE___UINT128_T

/* Hardening */
#define WC_RSA_BLINDING
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_NO_HARDEN_OFF        /* keep hardening on */

/* TLS 1.3 + QUIC */
#define WOLFSSL_TLS13
#define WOLFSSL_QUIC
#define HAVE_TLS_EXTENSIONS
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_SUPPORTED_CURVES

/* AEADs */
#define HAVE_AESGCM
#define WOLFSSL_AES_COUNTER     /* required by some HP paths */
#define WOLFSSL_AES_DIRECT      /* AES-ECB primitive for QUIC HP */
#define HAVE_AES_ECB            /* wolfSSL_EVP_aes_{128,256}_ecb for HP */
#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ONE_TIME_AUTH

/* Hashes */
#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

/* RSA — TLS 1.3 mandates PSS signatures with RSA */
#define WC_RSA_PSS
#define WOLFSSL_PSS_LONG_SALT
#define WOLFSSL_PSS_SALT_LEN_DISCOVER

/* KDF */
#define HAVE_HKDF

/* Asymmetric */
#define HAVE_ECC
#define ECC_USER_CURVES
#define HAVE_ECC256
#define HAVE_ECC384
#define HAVE_SUPPORTED_CURVES
#define HAVE_CURVE25519
#define HAVE_ED25519
#define HAVE_ED25519_VERIFY
#define ECC_SHAMIR
#define TFM_ECC256

/* TLS extensions used by QUIC */
#define HAVE_SESSION_TICKET
#define HAVE_ALPN
#define HAVE_SNI
#define HAVE_EARLY_DATA         /* 0-RTT, may go unused; cheap to enable */
#define HAVE_EX_DATA            /* required for SSL_{set,get}_app_data */
#define OPENSSL_EXTRA           /* exposes the *_ex_data and a few QUIC helpers */
#define WOLFSSL_HAVE_QSH_OFF

/* Single-precision math (fast, constant-time) */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_NO_DYN_STACK

/* Disable DH — TLS 1.3 only does ECDHE for our config; if a TLS 1.2
 * server picks DHE we'll just renegotiate or fail. */
#define NO_DH

/* Disable old / unused */
#define NO_OLD_TLS
#define NO_RC4
#define NO_DES3
#define NO_MD4
#define NO_DSA
#define NO_PSK
#define NO_PKCS12
#define NO_MAIN_DRIVER
#define NO_FILESYSTEM           /* we never load certs from disk */
#define NO_WRITE_TEMP_FILES
#define WOLFSSL_NO_TLS12_HASH_ONLY_OFF

/* IO: keep BSD socket fallback available; we never call it for QUIC,
 * but the symbols (EmbedReceive/EmbedSend) are referenced from internal.c
 * unconditionally. */

/* Logging — opt-in at build time */
#define DEBUG_WOLFSSL

#endif /* ANYWHERE_WOLFSSL_USER_SETTINGS_H */
