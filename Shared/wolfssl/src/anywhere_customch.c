/*
 * anywhere_customch.c
 *
 * Anywhere downstream: uTLS-style custom ClientHello injection for
 * wolfSSL 5.9.1. This file is wholly new downstream code — it does not
 * modify any upstream wolfSSL source. The hook it drives sits in
 * src/tls13.c SendTls13ClientHello (see MODIFICATIONS.md for the exact
 * patch hunk and upstream-diff sentinels).
 *
 * All symbols here are gated by ANYWHERE_CUSTOM_CLIENT_HELLO (set in
 * user_settings.h). With that define off, this translation unit
 * produces nothing and the whole feature compiles out.
 *
 * See MODIFICATIONS.md §"Invariants the caller must preserve" for the
 * consistency rules between the setter state and the injected body.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef ANYWHERE_CUSTOM_CLIENT_HELLO

#include <wolfssl/internal.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#ifdef HAVE_CURVE25519
    #include <wolfssl/wolfcrypt/curve25519.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

/* ============================================================
 * wolfSSL_UseClientHelloRaw
 *
 * Installs the build callback on a WOLFSSL*. Must be called before
 * wolfSSL_connect; setting it after the ClientHello has already been
 * emitted is a no-op for the current connection.
 * ============================================================ */
int wolfSSL_UseClientHelloRaw(WOLFSSL* ssl,
                              WOLFSSL_ClientHelloBuildCb cb,
                              void* ctx)
{
    if (ssl == NULL || cb == NULL)
        return BAD_FUNC_ARG;
    ssl->anywhereChCb  = cb;
    ssl->anywhereChCtx = ctx;
    return WOLFSSL_SUCCESS;
}

/* ============================================================
 * wolfSSL_SetClientHelloRandom
 *
 * ssl->arrays->clientRandom is the 32-byte value wolfSSL feeds into
 * every TLS 1.3 key derivation (HKDF-Extract("", client_random ||
 * server_random)), plus it's stored so HelloRetryRequest can resend
 * the same bytes. When we substitute a custom ClientHello, the
 * 32 bytes at offset 2 of our body must equal these bytes.
 *
 * InitSSL already allocated ssl->arrays when wolfSSL_new ran, so we
 * don't have to worry about that here.
 * ============================================================ */
int wolfSSL_SetClientHelloRandom(WOLFSSL* ssl, const unsigned char* random32)
{
    if (ssl == NULL || random32 == NULL)
        return BAD_FUNC_ARG;
    if (ssl->arrays == NULL)
        return BAD_FUNC_ARG;
    XMEMCPY(ssl->arrays->clientRandom, random32, RAN_LEN);
    return WOLFSSL_SUCCESS;
}

/* ============================================================
 * wolfSSL_SetClientHelloLegacySessionId
 *
 * Parks the caller's session_id bytes in ssl->session->sessionID so
 * GetTls13SessionId (tls13.c:4487) emits them into the wire body AND
 * the ServerHello echo validator (tls13.c:5701) sees them when the
 * server echoes them back.
 *
 * When our custom body overwrites wolfSSL's internal builder output
 * with a different session_id, the validator still compares against
 * ssl->session->sessionID — so without this setter the handshake dies
 * with INVALID_PARAMETER (-425).
 *
 * `ssl->session` is allocated by wolfSSL_new, so non-NULL by the time
 * any caller reaches us.
 * ============================================================ */
int wolfSSL_SetClientHelloLegacySessionId(WOLFSSL* ssl,
                                          const unsigned char* id,
                                          unsigned int idLen)
{
    if (ssl == NULL) return BAD_FUNC_ARG;
    if (idLen > ID_LEN) return BAD_FUNC_ARG;
    if (idLen > 0 && id == NULL) return BAD_FUNC_ARG;
    if (ssl->session == NULL) return BAD_FUNC_ARG;

    if (idLen > 0) {
        XMEMCPY(ssl->session->sessionID, id, idLen);
    }
    ssl->session->sessionIDSz = (byte)idLen;
    return WOLFSSL_SUCCESS;
}

/* ============================================================
 * wolfSSL_OfferCipherSuites
 *
 * Rewrites ssl->suites->suites[] from a wire-formatted list. Expects
 * the raw 2-byte-per-suite sequence (no 16-bit length prefix — i.e.
 * what gets serialised in ClientHello after the length field).
 *
 * AllocateSuites makes sure ssl->suites is ssl-local (it may have
 * been NULL, pointing at ctx->suites which we must not mutate).
 * ============================================================ */
int wolfSSL_OfferCipherSuites(WOLFSSL* ssl,
                              const unsigned char* wireBytes,
                              unsigned int wireLen)
{
    int ret;

    if (ssl == NULL || wireBytes == NULL)
        return BAD_FUNC_ARG;
    if (wireLen == 0 || (wireLen & 1) != 0)
        return BAD_FUNC_ARG;
    if (wireLen > WOLFSSL_MAX_SUITE_SZ)
        return BUFFER_E;

    ret = AllocateSuites(ssl);
    if (ret != 0)
        return ret;

    XMEMCPY(ssl->suites->suites, wireBytes, wireLen);
    ssl->suites->suiteSz  = (word16)wireLen;
    ssl->suites->setSuites = 1;
    return WOLFSSL_SUCCESS;
}

/* ============================================================
 * wolfSSL_OfferKeyShare
 *
 * Push a KeyShareEntry with a caller-owned (pub, priv) pair onto
 * ssl->extensions. Two things happen on it:
 *
 *   1. keyShareEntry->ke / ->keLen  — the public key, used for the
 *      wire serialisation that wolfSSL would normally do AND (via
 *      our tls13.c hook) that the caller's injected body already
 *      contains. Must match what the injected body announces.
 *
 *   2. keyShareEntry->key           — a fully-initialised wolfCrypt
 *      key struct (curve25519_key* or ecc_key*) holding the PRIVATE
 *      key. This is what TLSX_KeyShare_Process{X25519,Ecc} uses to
 *      derive the ECDH shared secret once ServerHello arrives. If
 *      this is NULL when the server picks the group, wolfSSL returns
 *      BAD_FUNC_ARG from the process path.
 *
 * We do (1) via TLSX_KeyShare_Use (upstream API, data != NULL path).
 * For (2) we import the raw private key into the appropriate wolfCrypt
 * struct and plug it into keyShareEntry->key directly.
 *
 * Supported groups: WOLFSSL_ECC_X25519, WOLFSSL_ECC_SECP256R1,
 * WOLFSSL_ECC_SECP384R1. Others return BAD_FUNC_ARG; extend as
 * needed — the PQ hybrid groups would require KyberKey setup here.
 * ============================================================ */

#ifdef HAVE_CURVE25519
static int AnywhereImportX25519Priv(WOLFSSL* ssl, KeyShareEntry* kse,
                                    const unsigned char* priv,
                                    unsigned int privLen,
                                    const unsigned char* pub,
                                    unsigned int pubLen)
{
    curve25519_key* key;
    int ret;

    if (privLen != CURVE25519_KEYSIZE || pubLen != CURVE25519_KEYSIZE)
        return BAD_FUNC_ARG;

    key = (curve25519_key*)XMALLOC(sizeof(*key), ssl->heap,
                                   DYNAMIC_TYPE_PRIVATE_KEY);
    if (key == NULL)
        return MEMORY_E;
    ret = wc_curve25519_init_ex(key, ssl->heap, ssl->devId);
    if (ret != 0) {
        XFREE(key, ssl->heap, DYNAMIC_TYPE_PRIVATE_KEY);
        return ret;
    }
    /* Clients emit public key little-endian on the wire (EC25519_LITTLE_ENDIAN);
     * wc_curve25519_import_private_raw_ex takes private LE too. */
    ret = wc_curve25519_import_private_raw_ex(priv, (word32)privLen,
                                              pub, (word32)pubLen,
                                              key, EC25519_LITTLE_ENDIAN);
    if (ret != 0) {
        wc_curve25519_free(key);
        XFREE(key, ssl->heap, DYNAMIC_TYPE_PRIVATE_KEY);
        return ret;
    }

    kse->key    = key;
    kse->keyLen = sizeof(*key);
    return 0;
}
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ECC
static int AnywhereImportEccPriv(WOLFSSL* ssl, KeyShareEntry* kse,
                                 word16 group,
                                 const unsigned char* priv,
                                 unsigned int privLen,
                                 const unsigned char* pub,
                                 unsigned int pubLen)
{
    ecc_key* key;
    int curveId;
    int ret;
    word32 fieldSz;

    switch (group) {
        case WOLFSSL_ECC_SECP256R1:
            curveId = ECC_SECP256R1; fieldSz = 32; break;
        case WOLFSSL_ECC_SECP384R1:
            curveId = ECC_SECP384R1; fieldSz = 48; break;
        default:
            return BAD_FUNC_ARG;
    }
    if (privLen != fieldSz)
        return BAD_FUNC_ARG;
    /* Public on the wire is uncompressed X9.63: 0x04 || X || Y. */
    if (pubLen != 1 + 2 * fieldSz || pub[0] != 0x04)
        return BAD_FUNC_ARG;

    key = (ecc_key*)XMALLOC(sizeof(*key), ssl->heap, DYNAMIC_TYPE_ECC);
    if (key == NULL)
        return MEMORY_E;
    ret = wc_ecc_init_ex(key, ssl->heap, ssl->devId);
    if (ret != 0) {
        XFREE(key, ssl->heap, DYNAMIC_TYPE_ECC);
        return ret;
    }

    /* Import the raw private + X || Y pair. The X9.63 byte is skipped
     * manually since wc_ecc_import_private_key_ex expects raw scalars. */
    {
        const unsigned char* x = pub + 1;
        const unsigned char* y = pub + 1 + fieldSz;
        ret = wc_ecc_import_unsigned(key, (byte*)x, (byte*)y,
                                     (byte*)priv, curveId);
    }
    if (ret != 0) {
        wc_ecc_free(key);
        XFREE(key, ssl->heap, DYNAMIC_TYPE_ECC);
        return ret;
    }

    kse->key    = key;
    kse->keyLen = sizeof(*key);
    return 0;
}
#endif /* HAVE_ECC */

int wolfSSL_OfferKeyShare(WOLFSSL* ssl, word16 group,
                          const unsigned char* pubKey, unsigned int pubKeyLen,
                          const unsigned char* privKey, unsigned int privKeyLen)
{
    KeyShareEntry* kse = NULL;
    byte*          pubCopy;
    int            ret;

    if (ssl == NULL || pubKey == NULL || privKey == NULL)
        return BAD_FUNC_ARG;
    if (pubKeyLen == 0 || privKeyLen == 0)
        return BAD_FUNC_ARG;

    /* TLSX_KeyShare_Use with data != NULL takes ownership of the
     * buffer and frees it via ssl->heap — give it a private copy. */
    pubCopy = (byte*)XMALLOC(pubKeyLen, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (pubCopy == NULL)
        return MEMORY_E;
    XMEMCPY(pubCopy, pubKey, pubKeyLen);

    ret = TLSX_KeyShare_Use(ssl, group, (word16)pubKeyLen, pubCopy,
                            &kse, &ssl->extensions);
    if (ret != 0) {
        XFREE(pubCopy, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        return ret;
    }
    if (kse == NULL)
        return WOLFSSL_FATAL_ERROR;

    switch (group) {
    #ifdef HAVE_CURVE25519
        case WOLFSSL_ECC_X25519:
            ret = AnywhereImportX25519Priv(ssl, kse, privKey, privKeyLen,
                                           pubKey, pubKeyLen);
            break;
    #endif
    #ifdef HAVE_ECC
        case WOLFSSL_ECC_SECP256R1:
        case WOLFSSL_ECC_SECP384R1:
            ret = AnywhereImportEccPriv(ssl, kse, group, privKey, privKeyLen,
                                        pubKey, pubKeyLen);
            break;
    #endif
        default:
            /* ke + keLen already set; entry exists in the extension list
             * but has no private key. wolfSSL will fail later with
             * BAD_FUNC_ARG out of the process path when the server picks
             * this group. Return BAD_FUNC_ARG here so the caller notices
             * at setter-call time. */
            return BAD_FUNC_ARG;
    }

    return ret == 0 ? WOLFSSL_SUCCESS : ret;
}

#endif /* ANYWHERE_CUSTOM_CLIENT_HELLO */
