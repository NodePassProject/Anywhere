//
//  CTLSKeyDerivation.c
//  Network Extension
//
//  TLS 1.3 key derivation using CommonCrypto (RFC 8446).
//

#include "CTLSKeyDerivation.h"
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonDigest.h>
#include <string.h>

// MARK: - Internal Helpers

/// Resolve cipher suite to HMAC algorithm, hash length, and key length.
static void get_suite_params(uint16_t cs, CCHmacAlgorithm *alg,
                             int *hash_len, int *key_len) {
    if (cs == TLS_AES_256_GCM_SHA384) {
        *alg = kCCHmacAlgSHA384;
        *hash_len = CC_SHA384_DIGEST_LENGTH; // 48
        *key_len = 32;
    } else {
        *alg = kCCHmacAlgSHA256;
        *hash_len = CC_SHA256_DIGEST_LENGTH; // 32
        *key_len = 16;
    }
}

/// SHA-256 or SHA-384 hash depending on cipher suite.
static void sha_hash(uint16_t cs, const void *data, size_t len, void *out) {
    if (cs == TLS_AES_256_GCM_SHA384) {
        CC_SHA384(data, (CC_LONG)len, out);
    } else {
        CC_SHA256(data, (CC_LONG)len, out);
    }
}

/// HKDF-Extract: PRK = HMAC(salt, IKM). Uses zero salt of hashLen if salt is empty.
static void hkdf_extract(CCHmacAlgorithm alg, int hash_len,
                          const uint8_t *salt, size_t salt_len,
                          const uint8_t *ikm, size_t ikm_len,
                          uint8_t *prk) {
    if (salt_len == 0) {
        uint8_t zero_salt[48] = {0};
        CCHmac(alg, zero_salt, hash_len, ikm, ikm_len, prk);
    } else {
        CCHmac(alg, salt, salt_len, ikm, ikm_len, prk);
    }
}

/// HKDF-Expand: output = T(1) || T(2) || ... truncated to length.
static void hkdf_expand(CCHmacAlgorithm alg, int hash_len,
                         const uint8_t *prk, size_t prk_len,
                         const uint8_t *info, size_t info_len,
                         uint8_t *out, int length) {
    uint8_t t[48]; // max hash output (SHA-384)
    int t_len = 0;
    int offset = 0;
    uint8_t counter = 1;

    while (offset < length) {
        CCHmacContext ctx;
        CCHmacInit(&ctx, alg, prk, prk_len);
        if (t_len > 0) {
            CCHmacUpdate(&ctx, t, t_len);
        }
        CCHmacUpdate(&ctx, info, info_len);
        CCHmacUpdate(&ctx, &counter, 1);
        CCHmacFinal(&ctx, t);
        t_len = hash_len;

        int to_copy = hash_len;
        if (offset + to_copy > length) {
            to_copy = length - offset;
        }
        memcpy(out + offset, t, to_copy);
        offset += to_copy;
        counter++;
    }
}

/// HKDF-Expand-Label(Secret, Label, Context, Length) per RFC 8446 §7.1.
static void hkdf_expand_label(CCHmacAlgorithm alg, int hash_len,
                               const uint8_t *secret, size_t secret_len,
                               const char *label,
                               const uint8_t *context, size_t context_len,
                               uint8_t *out, int length) {
    // Info = Length(2) || "tls13 " || Label || Context_len(1) || Context
    uint8_t info[256];
    int info_len = 0;
    size_t label_len = strlen(label);
    int full_label_len = 6 + (int)label_len; // "tls13 " prefix

    info[info_len++] = (uint8_t)(length >> 8);
    info[info_len++] = (uint8_t)(length & 0xFF);
    info[info_len++] = (uint8_t)full_label_len;
    memcpy(info + info_len, "tls13 ", 6);
    info_len += 6;
    memcpy(info + info_len, label, label_len);
    info_len += (int)label_len;
    info[info_len++] = (uint8_t)context_len;
    if (context_len > 0) {
        memcpy(info + info_len, context, context_len);
        info_len += (int)context_len;
    }

    hkdf_expand(alg, hash_len, secret, secret_len, info, info_len, out, length);
}

/// Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, Hash(Messages), hashLen).
static void derive_secret(uint16_t cs, CCHmacAlgorithm alg, int hash_len,
                           const uint8_t *secret, size_t secret_len,
                           const char *label,
                           const uint8_t *messages, size_t messages_len,
                           uint8_t *out) {
    uint8_t hash[48];
    sha_hash(cs, messages, messages_len, hash);
    hkdf_expand_label(alg, hash_len, secret, secret_len, label, hash, hash_len, out, hash_len);
}

// MARK: - Public API

int tls13_derive_handshake_keys(
    uint16_t cipher_suite,
    const uint8_t *shared_secret, size_t ss_len,
    const uint8_t *transcript, size_t transcript_len,
    uint8_t *out_hs_secret,
    uint8_t *out_client_key,
    uint8_t *out_client_iv,
    uint8_t *out_server_key,
    uint8_t *out_server_iv,
    uint8_t *out_client_traffic_secret)
{
    CCHmacAlgorithm alg;
    int hash_len, key_len;
    get_suite_params(cipher_suite, &alg, &hash_len, &key_len);

    uint8_t zero_ikm[48] = {0};

    // Early Secret = HKDF-Extract(salt=0, IKM=0)
    uint8_t early_secret[48];
    hkdf_extract(alg, hash_len, NULL, 0, zero_ikm, hash_len, early_secret);

    // Derive-Secret(Early Secret, "derived", "")
    uint8_t derived_early[48];
    derive_secret(cipher_suite, alg, hash_len,
                  early_secret, hash_len, "derived", NULL, 0, derived_early);

    // Handshake Secret = HKDF-Extract(salt=derived, IKM=shared_secret)
    hkdf_extract(alg, hash_len, derived_early, hash_len,
                 shared_secret, ss_len, out_hs_secret);

    // client_handshake_traffic_secret
    derive_secret(cipher_suite, alg, hash_len,
                  out_hs_secret, hash_len, "c hs traffic",
                  transcript, transcript_len, out_client_traffic_secret);

    // client key + IV
    hkdf_expand_label(alg, hash_len, out_client_traffic_secret, hash_len,
                      "key", NULL, 0, out_client_key, key_len);
    hkdf_expand_label(alg, hash_len, out_client_traffic_secret, hash_len,
                      "iv", NULL, 0, out_client_iv, 12);

    // server_handshake_traffic_secret
    uint8_t server_hts[48];
    derive_secret(cipher_suite, alg, hash_len,
                  out_hs_secret, hash_len, "s hs traffic",
                  transcript, transcript_len, server_hts);

    // server key + IV
    hkdf_expand_label(alg, hash_len, server_hts, hash_len,
                      "key", NULL, 0, out_server_key, key_len);
    hkdf_expand_label(alg, hash_len, server_hts, hash_len,
                      "iv", NULL, 0, out_server_iv, 12);

    return 0;
}

int tls13_derive_application_keys(
    uint16_t cipher_suite,
    const uint8_t *hs_secret, size_t hs_len,
    const uint8_t *transcript, size_t transcript_len,
    uint8_t *out_client_key,
    uint8_t *out_client_iv,
    uint8_t *out_server_key,
    uint8_t *out_server_iv)
{
    CCHmacAlgorithm alg;
    int hash_len, key_len;
    get_suite_params(cipher_suite, &alg, &hash_len, &key_len);

    uint8_t zero_ikm[48] = {0};

    // Derive-Secret(handshake_secret, "derived", "")
    uint8_t derived_hs[48];
    derive_secret(cipher_suite, alg, hash_len,
                  hs_secret, hs_len, "derived", NULL, 0, derived_hs);

    // Master Secret = HKDF-Extract(salt=derived, IKM=0)
    uint8_t master_secret[48];
    hkdf_extract(alg, hash_len, derived_hs, hash_len,
                 zero_ikm, hash_len, master_secret);

    // client_application_traffic_secret
    uint8_t client_ats[48];
    derive_secret(cipher_suite, alg, hash_len,
                  master_secret, hash_len, "c ap traffic",
                  transcript, transcript_len, client_ats);

    hkdf_expand_label(alg, hash_len, client_ats, hash_len,
                      "key", NULL, 0, out_client_key, key_len);
    hkdf_expand_label(alg, hash_len, client_ats, hash_len,
                      "iv", NULL, 0, out_client_iv, 12);

    // server_application_traffic_secret
    uint8_t server_ats[48];
    derive_secret(cipher_suite, alg, hash_len,
                  master_secret, hash_len, "s ap traffic",
                  transcript, transcript_len, server_ats);

    hkdf_expand_label(alg, hash_len, server_ats, hash_len,
                      "key", NULL, 0, out_server_key, key_len);
    hkdf_expand_label(alg, hash_len, server_ats, hash_len,
                      "iv", NULL, 0, out_server_iv, 12);

    return 0;
}

int tls13_compute_finished(
    uint16_t cipher_suite,
    const uint8_t *client_traffic_secret, size_t secret_len,
    const uint8_t *transcript, size_t transcript_len,
    uint8_t *out_verify_data)
{
    CCHmacAlgorithm alg;
    int hash_len, key_len;
    get_suite_params(cipher_suite, &alg, &hash_len, &key_len);

    // finished_key = HKDF-Expand-Label(client_traffic_secret, "finished", "", hashLen)
    uint8_t finished_key[48];
    hkdf_expand_label(alg, hash_len, client_traffic_secret, secret_len,
                      "finished", NULL, 0, finished_key, hash_len);

    // verify_data = HMAC(finished_key, transcript_hash)
    uint8_t th[48];
    sha_hash(cipher_suite, transcript, transcript_len, th);

    CCHmac(alg, finished_key, hash_len, th, hash_len, out_verify_data);

    return 0;
}

int tls13_transcript_hash(
    uint16_t cipher_suite,
    const uint8_t *messages, size_t messages_len,
    uint8_t *out_hash)
{
    sha_hash(cipher_suite, messages, messages_len, out_hash);
    return 0;
}
