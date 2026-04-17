//
//  user_settings.h
//  Anywhere
//
//  Created by Argsment Limited on 4/16/26.
//

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
#define NO_ECC521
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
#define WOLFSSL_EARLY_DATA      /* 0-RTT — gates wolfSSL_{set_quic,get}_early_data_* */
#define HAVE_EX_DATA            /* required for SSL_{set,get}_app_data */
#define OPENSSL_EXTRA           /* exposes the *_ex_data and a few QUIC helpers */
#define WOLFSSL_HAVE_QSH_OFF

/* Single-precision math (fast, constant-time) */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_NO_DYN_STACK

/* ARM64 NEON acceleration. Apple Silicon and every 64-bit Apple mobile SoC
 * (A7+) has NEON, the ARMv8 AES/SHA crypto extensions, and — from the A11
 * onward — the ARMv8.2 SHA-512 extension. The upstream asm sources sit
 * under wolfcrypt/src/port/arm/ and wolfcrypt/src/sp_arm64.c; they become
 * empty translation units on x86_64 simulator builds thanks to the
 * `__aarch64__` guard inside each file, so no target filtering needed.
 *
 *   WOLFSSL_ARMASM        — master gate for the port/arm/* sources.
 *   WOLFSSL_ARMASM_INLINE — pick the intrinsic-C variants (*_c.c) instead
 *                           of the hand-rolled .S files; clang auto-targets
 *                           aarch64+crypto with -target arm64-apple, so no
 *                           extra -march flag is needed.
 *   WOLFSSL_ARMASM_NO_HW_CRYPTO — force AES and SHA-256 onto the NEON-only
 *                           paths. The AESE/AESMC + SHA256H/SHA256H2
 *                           intrinsic paths in wolfSSL v5.9.1's generated
 *                           armv8-aes-asm_c.c / armv8-sha256-asm_c.c
 *                           produce wrong output on iOS arm64 — QUIC
 *                           Initial packets come out with either a bad
 *                           header-protection mask or a bad GCM tag, the
 *                           server drops them silently, and the handshake
 *                           stalls at WANT_READ. NEON is still ~2x the
 *                           baseline C path, so this is a cheap downgrade
 *                           until wolfSSL upstream repairs the generated
 *                           HW-crypto path and we re-vendor.
 *   WOLFSSL_SP_ARM64_ASM  — swap sp_c64.c's body out for sp_arm64.c's
 *                           hand-vectorised RSA/ECC scalar primitives.
 *                           Unaffected by the HW-crypto issue above. */
#if defined(__aarch64__)
#  define WOLFSSL_ARMASM
#  define WOLFSSL_ARMASM_INLINE
#  define WOLFSSL_ARMASM_NO_HW_CRYPTO
#  define WOLFSSL_SP_ARM64_ASM
#endif

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

/* Downstream feature: uTLS-style custom ClientHello injection. Gates every
 * source-level patch listed in MODIFICATIONS.md. Leaving this define on
 * compiles the hooks in; turning it off restores bit-for-bit upstream
 * behavior of wolfSSL 5.9.1.
 *
 * Enables:
 *   - wolfSSL_UseClientHelloRaw / SetClientHelloRandom /
 *     OfferKeyShare / OfferCipherSuites in src/anywhere_customch.c
 *   - the branch in SendTls13ClientHello that substitutes caller-provided
 *     ClientHello body bytes for wolfSSL's internal builder. */
#define ANYWHERE_CUSTOM_CLIENT_HELLO

/* IO: keep BSD socket fallback available; we never call it for QUIC,
 * but the symbols (EmbedReceive/EmbedSend) are referenced from internal.c
 * unconditionally. */

/* Logging — opt-in at build time */
/* #define DEBUG_WOLFSSL */

#endif /* ANYWHERE_WOLFSSL_USER_SETTINGS_H */
