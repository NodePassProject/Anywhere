#include "SudokuOutbound.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__) && !defined(SUDOKU_LOCAL_OPENSSL_BACKEND)
#  define SUDOKU_APPLE_SWIFT_BACKEND 1
#else
#  define SUDOKU_APPLE_SWIFT_BACKEND 0
#endif

#if SUDOKU_APPLE_SWIFT_BACKEND
#  include <CommonCrypto/CommonDigest.h>
#  include <CommonCrypto/CommonHMAC.h>
#else
#  include <sodium.h>
#  include <openssl/evp.h>
#  include <openssl/kdf.h>
#  include <openssl/hmac.h>
#  include <openssl/rand.h>
#  include <openssl/sha.h>
#  include <openssl/ssl.h>
#  include <openssl/x509.h>
#endif

extern int sudoku_swift_socket_factory_open(void *ctx, const char *host, uint16_t port);
extern int sudoku_swift_socket_factory_open_ex(
    void *ctx,
    const char *host,
    uint16_t port,
    int use_tls,
    const char *server_name
);
extern int sudoku_swift_crypto_aead_encrypt(
    uint8_t *dest,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    int32_t aead_kind
);
extern int sudoku_swift_crypto_aead_decrypt(
    uint8_t *dest,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *aad,
    size_t aad_len,
    int32_t aead_kind
);
extern int sudoku_swift_crypto_x25519_generate(uint8_t *private_key, uint8_t *public_key);
extern int sudoku_swift_crypto_x25519_shared(
    const uint8_t *private_key,
    const uint8_t *peer_public_key,
    uint8_t *shared_key
);

#if SUDOKU_APPLE_SWIFT_BACKEND
#  define SUDOKU_SWIFT_AEAD_AES128_GCM_LOCAL 0
#  define SUDOKU_SWIFT_AEAD_CHACHA20_POLY1305_LOCAL 1
#  define SUDOKU_DIGEST_MAX_SIZE 32
#else
#  define SUDOKU_DIGEST_MAX_SIZE EVP_MAX_MD_SIZE
#endif

typedef enum {
    SUDOKU_TRANSPORT_RAW = 0,
    SUDOKU_TRANSPORT_WS = 1,
    SUDOKU_TRANSPORT_HTTP_STREAM = 2,
    SUDOKU_TRANSPORT_HTTP_POLL = 3
} sudoku_transport_kind_t;

typedef enum {
    SUDOKU_AEAD_CHACHA20 = 0,
    SUDOKU_AEAD_AES128GCM = 1,
    SUDOKU_AEAD_NONE = 2
} sudoku_aead_kind_t;

typedef struct {
    int fd;
#if !SUDOKU_APPLE_SWIFT_BACKEND
    SSL_CTX *ssl_ctx;
    SSL *ssl;
#endif
    uint8_t read_buf[4096];
    size_t read_len;
    size_t read_off;
} sudoku_http_conn_t;

typedef struct sudoku_byte_chunk {
    uint8_t *data;
    size_t len;
    size_t off;
    struct sudoku_byte_chunk *next;
} sudoku_byte_chunk_t;

typedef struct {
    sudoku_http_conn_t *conn;
    int status_code;
    int chunked;
    int close_delimited;
    int done;
    size_t content_remaining;
    size_t chunk_remaining;
} sudoku_http_body_reader_t;

typedef struct {
    sudoku_outbound_config_t cfg;
    sudoku_transport_kind_t mode;
    char header_host[320];
    char token[256];
    char session_path[256];
    char pull_path[384];
    char push_path[384];
    char fin_path[384];
    char close_path[384];

    pthread_mutex_t mu;
    pthread_cond_t rx_cond;
    pthread_cond_t tx_cond;
    sudoku_byte_chunk_t *rx_head;
    sudoku_byte_chunk_t *rx_tail;
    sudoku_byte_chunk_t *tx_head;
    sudoku_byte_chunk_t *tx_tail;
    int closed;
    int fatal;

    pthread_mutex_t req_mu;
    sudoku_http_conn_t *active_pull;
    sudoku_http_conn_t *active_push;

    pthread_t pull_thread;
    pthread_t push_thread;
    int pull_started;
    int push_started;
} sudoku_httpmask_state_t;

typedef struct {
    int fd;
#if !SUDOKU_APPLE_SWIFT_BACKEND
    SSL_CTX *ssl_ctx;
    SSL *ssl;
#endif
    sudoku_transport_kind_t kind;
    int obfs_enabled;
    int pure_downlink;
    const sudoku_table_t *uplink_table;
    const sudoku_table_t *downlink_table;
    sudoku_splitmix64_t rng;
    uint64_t padding_threshold;
    sudoku_decoder_t pure_decoder;
    sudoku_packed_decoder_t packed_decoder;
    uint8_t plain_buf[65536];
    size_t plain_len;
    size_t plain_off;

    uint8_t rx_buf[65536];
    size_t rx_len;
    size_t rx_off;

    sudoku_httpmask_state_t *httpmask;

    pthread_mutex_t read_mu;
    pthread_mutex_t write_mu;
} sudoku_transport_t;

typedef struct {
    uint8_t base_send[32];
    uint8_t base_recv[32];
} sudoku_record_keys_t;

typedef struct {
    sudoku_transport_t *transport;
    sudoku_aead_kind_t method;
    sudoku_record_keys_t keys;

    pthread_mutex_t write_mu;
    pthread_mutex_t read_mu;

    uint32_t send_epoch;
    uint64_t send_seq;
    int64_t send_bytes;
    uint32_t send_epoch_updates;

    uint32_t recv_epoch;
    uint64_t recv_seq;
    int recv_initialized;

#if !SUDOKU_APPLE_SWIFT_BACKEND
    EVP_CIPHER_CTX *send_ctx;
    EVP_CIPHER_CTX *recv_ctx;
#endif
    uint32_t send_ctx_epoch;
    uint32_t recv_ctx_epoch;

    uint8_t read_buf[65536];
    size_t read_len;
    size_t read_off;
} sudoku_record_conn_t;

struct sudoku_client_conn {
    sudoku_transport_t *transport;
    sudoku_record_conn_t *record;
    sudoku_table_pair_t tables;
};

struct sudoku_uot_client {
    sudoku_transport_t *transport;
    sudoku_record_conn_t *record;
    sudoku_table_pair_t tables;
};

typedef struct sudoku_mux_chunk {
    uint8_t *data;
    size_t len;
    size_t off;
    struct sudoku_mux_chunk *next;
} sudoku_mux_chunk_t;

struct sudoku_mux_client;

struct sudoku_mux_stream {
    struct sudoku_mux_client *client;
    uint32_t id;
    int closed;
    int removed;
    sudoku_mux_chunk_t *head;
    sudoku_mux_chunk_t *tail;
    pthread_mutex_t mu;
    pthread_cond_t cond;
    struct sudoku_mux_stream *next;
};

struct sudoku_mux_client {
    sudoku_transport_t *transport;
    sudoku_record_conn_t *record;
    sudoku_table_pair_t tables;

    pthread_t reader_thread;
    int reader_started;

    pthread_mutex_t mu;
    pthread_mutex_t write_mu;

    struct sudoku_mux_stream *streams;
    struct sudoku_mux_stream *retired_streams;
    uint32_t next_stream_id;
    int closed;
};

static const uint32_t SUDOKU_KEY_UPDATE_AFTER_BYTES = 32u << 20;
static const size_t SUDOKU_MAX_CUSTOM_TABLES = 16;
static const size_t SUDOKU_MAX_CUSTOM_TABLE_LEN = 15;
static const uint32_t SUDOKU_MUX_MAX_FRAME_SIZE = 256u * 1024u;
static const uint32_t SUDOKU_MUX_MAX_DATA_PAYLOAD = 128u * 1024u;

void sudoku_uot_client_close(sudoku_uot_client_t *client);
void sudoku_mux_stream_close(sudoku_mux_stream_t *stream);
void sudoku_mux_client_close(sudoku_mux_client_t *client);
static void sudoku_byte_chunk_free_all(sudoku_byte_chunk_t *chunk);
static void sudoku_httpmask_mark_closed(sudoku_httpmask_state_t *state, int fatal);
static void sudoku_httpmask_interrupt_active(sudoku_httpmask_state_t *state);
static int sudoku_httpmask_best_effort_post(sudoku_httpmask_state_t *state, const char *path);
static int sudoku_tcp_connect_ex(
    const sudoku_outbound_config_t *cfg,
    const char *host,
    uint16_t port,
    int use_tls,
    const char *server_name
);

static void sudoku_hex_encode(const uint8_t *src, size_t len, char *out) {
    static const char *hex = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; ++i) {
        out[i * 2] = hex[src[i] >> 4];
        out[i * 2 + 1] = hex[src[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static void sudoku_sha256_bytes(const uint8_t *data, size_t len, uint8_t out[32]) {
#if SUDOKU_APPLE_SWIFT_BACKEND
    CC_SHA256(data, (CC_LONG)len, out);
#else
    SHA256(data, len, out);
#endif
}

static void sudoku_sha256_string(const char *s, uint8_t out[32]) {
    sudoku_sha256_bytes((const uint8_t *)s, strlen(s), out);
}

static int sudoku_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int sudoku_hex_decode(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t len = strlen(hex);
    size_t i;
    if ((len & 1u) != 0 || out_cap < len / 2) {
        return -1;
    }
    for (i = 0; i < len; i += 2) {
        int hi = sudoku_hex_nibble(hex[i]);
        int lo = sudoku_hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    if (out_len) {
        *out_len = len / 2;
    }
    return 0;
}

typedef struct {
    const uint8_t *data;
    size_t len;
} sudoku_bytespan_t;

static int sudoku_hmac_sha256_parts(
    const uint8_t *key,
    size_t key_len,
    const sudoku_bytespan_t *parts,
    size_t part_count,
    uint8_t out[32]
) {
    unsigned int mac_len = 0;
    uint8_t stack_buf[256];
    uint8_t *msg = stack_buf;
    size_t total = 0;
    size_t off = 0;
    size_t i;

    for (i = 0; i < part_count; ++i) {
        total += parts[i].len;
    }

    if (total > sizeof(stack_buf)) {
        msg = (uint8_t *)malloc(total);
        if (!msg) return -1;
    }

    for (i = 0; i < part_count; ++i) {
        if (!parts[i].data || parts[i].len == 0) continue;
        memcpy(msg + off, parts[i].data, parts[i].len);
        off += parts[i].len;
    }

#if SUDOKU_APPLE_SWIFT_BACKEND
    CCHmac(kCCHmacAlgSHA256, key, key_len, msg, total, out);
    mac_len = 32;
#else
    if (!HMAC(EVP_sha256(), key, (int)key_len, msg, total, out, &mac_len) || mac_len != 32) {
        if (msg != stack_buf) free(msg);
        return -1;
    }
#endif
    if (msg != stack_buf) free(msg);
    return mac_len == 32 ? 0 : -1;
}

static int sudoku_set_socket_common_opts(int fd) {
    int one = 1;
    if (fd < 0) return -1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    return 0;
}

#if SUDOKU_APPLE_SWIFT_BACKEND
typedef struct {
    uint64_t v[5];
} sudoku_fe25519_t;

typedef struct {
    sudoku_fe25519_t x;
    sudoku_fe25519_t y;
    sudoku_fe25519_t z;
    sudoku_fe25519_t t;
} sudoku_ed25519_point_t;

static const uint64_t SUDOKU_FE_MASK = ((uint64_t)1 << 51) - 1;
static const uint64_t SUDOKU_FE_P[5] = {
    2251799813685229ULL,
    2251799813685247ULL,
    2251799813685247ULL,
    2251799813685247ULL,
    2251799813685247ULL
};
static const uint8_t SUDOKU_ED25519_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};
static const uint8_t SUDOKU_FE_P_MINUS_2[32] = {
    0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};
static const sudoku_fe25519_t SUDOKU_FE_D2 = {{
    1859910466990425ULL,
    932731440258426ULL,
    1072319116312658ULL,
    1815898335770999ULL,
    633789495995903ULL
}};
static const sudoku_fe25519_t SUDOKU_ED25519_BASE_X = {{
    1738742601995546ULL,
    1146398526822698ULL,
    2070867633025821ULL,
    562264141797630ULL,
    587772402128613ULL
}};
static const sudoku_fe25519_t SUDOKU_ED25519_BASE_Y = {{
    1801439850948184ULL,
    1351079888211148ULL,
    450359962737049ULL,
    900719925474099ULL,
    1801439850948198ULL
}};

static void sudoku_fe_zero(sudoku_fe25519_t *h) {
    memset(h, 0, sizeof(*h));
}

static void sudoku_fe_one(sudoku_fe25519_t *h) {
    sudoku_fe_zero(h);
    h->v[0] = 1;
}

static void sudoku_fe_carry(sudoku_fe25519_t *h) {
    uint64_t carry;
    carry = h->v[0] >> 51; h->v[0] &= SUDOKU_FE_MASK; h->v[1] += carry;
    carry = h->v[1] >> 51; h->v[1] &= SUDOKU_FE_MASK; h->v[2] += carry;
    carry = h->v[2] >> 51; h->v[2] &= SUDOKU_FE_MASK; h->v[3] += carry;
    carry = h->v[3] >> 51; h->v[3] &= SUDOKU_FE_MASK; h->v[4] += carry;
    carry = h->v[4] >> 51; h->v[4] &= SUDOKU_FE_MASK; h->v[0] += carry * 19;
    carry = h->v[0] >> 51; h->v[0] &= SUDOKU_FE_MASK; h->v[1] += carry;
}

static int sudoku_fe_gte_p(const sudoku_fe25519_t *h) {
    int i;
    for (i = 4; i >= 0; --i) {
        if (h->v[i] > SUDOKU_FE_P[i]) return 1;
        if (h->v[i] < SUDOKU_FE_P[i]) return 0;
    }
    return 1;
}

static void sudoku_fe_sub_p(sudoku_fe25519_t *h) {
    uint64_t borrow = 0;
    size_t i;
    for (i = 0; i < 5; ++i) {
        uint64_t sub = SUDOKU_FE_P[i] + borrow;
        uint64_t next_borrow = h->v[i] < sub;
        h->v[i] -= sub;
        borrow = next_borrow;
    }
}

static void sudoku_fe_normalize(sudoku_fe25519_t *h) {
    sudoku_fe_carry(h);
    sudoku_fe_carry(h);
    if (sudoku_fe_gte_p(h)) sudoku_fe_sub_p(h);
}

static void sudoku_fe_add(sudoku_fe25519_t *h, const sudoku_fe25519_t *f, const sudoku_fe25519_t *g) {
    size_t i;
    for (i = 0; i < 5; ++i) h->v[i] = f->v[i] + g->v[i];
    sudoku_fe_carry(h);
}

static void sudoku_fe_sub(sudoku_fe25519_t *h, const sudoku_fe25519_t *f, const sudoku_fe25519_t *g) {
    size_t i;
    for (i = 0; i < 5; ++i) h->v[i] = f->v[i] + 4 * SUDOKU_FE_P[i] - g->v[i];
    sudoku_fe_carry(h);
}

static void sudoku_fe_mul(sudoku_fe25519_t *h, const sudoku_fe25519_t *f, const sudoku_fe25519_t *g) {
    __uint128_t t0, t1, t2, t3, t4;
    uint64_t carry;
    t0 = (__uint128_t)f->v[0] * g->v[0] +
         19 * ((__uint128_t)f->v[1] * g->v[4] + (__uint128_t)f->v[2] * g->v[3] +
               (__uint128_t)f->v[3] * g->v[2] + (__uint128_t)f->v[4] * g->v[1]);
    t1 = (__uint128_t)f->v[0] * g->v[1] + (__uint128_t)f->v[1] * g->v[0] +
         19 * ((__uint128_t)f->v[2] * g->v[4] + (__uint128_t)f->v[3] * g->v[3] +
               (__uint128_t)f->v[4] * g->v[2]);
    t2 = (__uint128_t)f->v[0] * g->v[2] + (__uint128_t)f->v[1] * g->v[1] +
         (__uint128_t)f->v[2] * g->v[0] +
         19 * ((__uint128_t)f->v[3] * g->v[4] + (__uint128_t)f->v[4] * g->v[3]);
    t3 = (__uint128_t)f->v[0] * g->v[3] + (__uint128_t)f->v[1] * g->v[2] +
         (__uint128_t)f->v[2] * g->v[1] + (__uint128_t)f->v[3] * g->v[0] +
         19 * ((__uint128_t)f->v[4] * g->v[4]);
    t4 = (__uint128_t)f->v[0] * g->v[4] + (__uint128_t)f->v[1] * g->v[3] +
         (__uint128_t)f->v[2] * g->v[2] + (__uint128_t)f->v[3] * g->v[1] +
         (__uint128_t)f->v[4] * g->v[0];

    carry = (uint64_t)(t0 >> 51); t1 += carry; h->v[0] = (uint64_t)t0 & SUDOKU_FE_MASK;
    carry = (uint64_t)(t1 >> 51); t2 += carry; h->v[1] = (uint64_t)t1 & SUDOKU_FE_MASK;
    carry = (uint64_t)(t2 >> 51); t3 += carry; h->v[2] = (uint64_t)t2 & SUDOKU_FE_MASK;
    carry = (uint64_t)(t3 >> 51); t4 += carry; h->v[3] = (uint64_t)t3 & SUDOKU_FE_MASK;
    carry = (uint64_t)(t4 >> 51); h->v[4] = (uint64_t)t4 & SUDOKU_FE_MASK; h->v[0] += carry * 19;
    sudoku_fe_carry(h);
}

static void sudoku_fe_sq(sudoku_fe25519_t *h, const sudoku_fe25519_t *f) {
    sudoku_fe_mul(h, f, f);
}

static int sudoku_exp_bit(const uint8_t exp[32], int bit) {
    return (exp[bit >> 3] >> (bit & 7)) & 1;
}

static void sudoku_fe_invert(sudoku_fe25519_t *out, const sudoku_fe25519_t *z) {
    sudoku_fe25519_t result;
    int bit;
    sudoku_fe_one(&result);
    for (bit = 254; bit >= 0; --bit) {
        sudoku_fe_sq(&result, &result);
        if (sudoku_exp_bit(SUDOKU_FE_P_MINUS_2, bit)) {
            sudoku_fe_mul(&result, &result, z);
        }
    }
    *out = result;
}

static void sudoku_fe_tobytes(uint8_t out[32], const sudoku_fe25519_t *in) {
    sudoku_fe25519_t h = *in;
    size_t i;
    sudoku_fe_normalize(&h);
    for (i = 0; i < 32; ++i) {
        unsigned bit = (unsigned)(i * 8);
        unsigned limb = bit / 51;
        unsigned shift = bit % 51;
        __uint128_t v = h.v[limb] >> shift;
        if (limb + 1 < 5 && shift > 43) {
            v |= (__uint128_t)h.v[limb + 1] << (51 - shift);
        }
        out[i] = (uint8_t)v;
    }
}

static int sudoku_fe_is_odd(const sudoku_fe25519_t *f) {
    uint8_t bytes[32];
    sudoku_fe_tobytes(bytes, f);
    return bytes[0] & 1;
}

static void sudoku_ed_point_identity(sudoku_ed25519_point_t *p) {
    sudoku_fe_zero(&p->x);
    sudoku_fe_one(&p->y);
    sudoku_fe_one(&p->z);
    sudoku_fe_zero(&p->t);
}

static void sudoku_ed_point_base(sudoku_ed25519_point_t *p) {
    p->x = SUDOKU_ED25519_BASE_X;
    p->y = SUDOKU_ED25519_BASE_Y;
    sudoku_fe_one(&p->z);
    sudoku_fe_mul(&p->t, &p->x, &p->y);
}

static void sudoku_ed_point_add(sudoku_ed25519_point_t *r, const sudoku_ed25519_point_t *p, const sudoku_ed25519_point_t *q) {
    sudoku_fe25519_t a, b, c, d, e, f, g, h, tmp1, tmp2;
    sudoku_fe_sub(&tmp1, &p->y, &p->x);
    sudoku_fe_sub(&tmp2, &q->y, &q->x);
    sudoku_fe_mul(&a, &tmp1, &tmp2);
    sudoku_fe_add(&tmp1, &p->y, &p->x);
    sudoku_fe_add(&tmp2, &q->y, &q->x);
    sudoku_fe_mul(&b, &tmp1, &tmp2);
    sudoku_fe_mul(&c, &p->t, &q->t);
    sudoku_fe_mul(&c, &c, &SUDOKU_FE_D2);
    sudoku_fe_mul(&d, &p->z, &q->z);
    sudoku_fe_add(&d, &d, &d);
    sudoku_fe_sub(&e, &b, &a);
    sudoku_fe_sub(&f, &d, &c);
    sudoku_fe_add(&g, &d, &c);
    sudoku_fe_add(&h, &b, &a);
    sudoku_fe_mul(&r->x, &e, &f);
    sudoku_fe_mul(&r->y, &g, &h);
    sudoku_fe_mul(&r->t, &e, &h);
    sudoku_fe_mul(&r->z, &f, &g);
}

static void sudoku_ed_point_double(sudoku_ed25519_point_t *r, const sudoku_ed25519_point_t *p) {
    sudoku_fe25519_t a, b, c, d, e, f, g, h, tmp;
    sudoku_fe_sq(&a, &p->x);
    sudoku_fe_sq(&b, &p->y);
    sudoku_fe_sq(&c, &p->z);
    sudoku_fe_add(&c, &c, &c);
    sudoku_fe_zero(&tmp);
    sudoku_fe_sub(&d, &tmp, &a);
    sudoku_fe_add(&tmp, &p->x, &p->y);
    sudoku_fe_sq(&e, &tmp);
    sudoku_fe_sub(&e, &e, &a);
    sudoku_fe_sub(&e, &e, &b);
    sudoku_fe_add(&g, &d, &b);
    sudoku_fe_sub(&f, &g, &c);
    sudoku_fe_sub(&h, &d, &b);
    sudoku_fe_mul(&r->x, &e, &f);
    sudoku_fe_mul(&r->y, &g, &h);
    sudoku_fe_mul(&r->t, &e, &h);
    sudoku_fe_mul(&r->z, &f, &g);
}

static int sudoku_scalar_gte_l(const uint8_t s[32]) {
    int i;
    for (i = 31; i >= 0; --i) {
        if (s[i] > SUDOKU_ED25519_L[i]) return 1;
        if (s[i] < SUDOKU_ED25519_L[i]) return 0;
    }
    return 1;
}

static void sudoku_scalar_sub_l(uint8_t s[32]) {
    unsigned borrow = 0;
    size_t i;
    for (i = 0; i < 32; ++i) {
        unsigned sub = (unsigned)SUDOKU_ED25519_L[i] + borrow;
        unsigned cur = s[i];
        s[i] = (uint8_t)(cur - sub);
        borrow = cur < sub;
    }
}

static void sudoku_scalar_add(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]) {
    unsigned carry = 0;
    size_t i;
    for (i = 0; i < 32; ++i) {
        unsigned sum = (unsigned)a[i] + (unsigned)b[i] + carry;
        out[i] = (uint8_t)sum;
        carry = sum >> 8;
    }
    if (carry || sudoku_scalar_gte_l(out)) sudoku_scalar_sub_l(out);
}

static void sudoku_ed25519_scalar_base_public(const uint8_t scalar[32], uint8_t out[32]) {
    sudoku_ed25519_point_t result;
    sudoku_ed25519_point_t base;
    int bit;
    sudoku_ed_point_identity(&result);
    sudoku_ed_point_base(&base);
    for (bit = 255; bit >= 0; --bit) {
        sudoku_ed25519_point_t doubled;
        sudoku_ed_point_double(&doubled, &result);
        result = doubled;
        if ((scalar[bit >> 3] >> (bit & 7)) & 1) {
            sudoku_ed25519_point_t added;
            sudoku_ed_point_add(&added, &result, &base);
            result = added;
        }
    }
    {
        sudoku_fe25519_t z_inv, x, y;
        sudoku_fe_invert(&z_inv, &result.z);
        sudoku_fe_mul(&x, &result.x, &z_inv);
        sudoku_fe_mul(&y, &result.y, &z_inv);
        sudoku_fe_tobytes(out, &y);
        if (sudoku_fe_is_odd(&x)) out[31] |= 0x80;
        else out[31] &= 0x7f;
    }
}
#endif

static int sudoku_public_key_from_private(
    const uint8_t *private_key,
    size_t private_len,
    uint8_t public_key[32]
) {
#if SUDOKU_APPLE_SWIFT_BACKEND
    uint8_t scalar[32];
    if (private_len == 32) {
        memcpy(scalar, private_key, 32);
    } else if (private_len == 64) {
        sudoku_scalar_add(scalar, private_key, private_key + 32);
    } else {
        return -1;
    }
    sudoku_ed25519_scalar_base_public(scalar, public_key);
    return 0;
#else
    uint8_t scalar[32];
    if (private_len == 32) {
        memcpy(scalar, private_key, 32);
    } else if (private_len == 64) {
        crypto_core_ed25519_scalar_add(scalar, private_key, private_key + 32);
    } else {
        return -1;
    }
    return crypto_scalarmult_ed25519_base_noclamp(public_key, scalar);
#endif
}

static int sudoku_key_is_public_point(const uint8_t *key, size_t key_len) {
#if SUDOKU_APPLE_SWIFT_BACKEND
    (void)key;
    return key_len == 32;
#else
    return key_len == 32 && crypto_core_ed25519_is_valid_point(key) == 1;
#endif
}

static const char *sudoku_seed_key_hex(const sudoku_outbound_config_t *cfg) {
    if (cfg && cfg->public_key_hex[0]) return cfg->public_key_hex;
    return cfg ? cfg->key_hex : "";
}

static int sudoku_normalize_key(sudoku_outbound_config_t *cfg) {
    uint8_t raw[64];
    size_t raw_len = 0;
    uint8_t public_key[32];
    if (sudoku_hex_decode(cfg->key_hex, raw, sizeof(raw), &raw_len) != 0) {
        return -1;
    }

    memset(cfg->private_key, 0, sizeof(cfg->private_key));
    cfg->private_key_len = 0;

    if (cfg->key_kind == SUDOKU_KEY_PUBLIC ||
        (cfg->key_kind == SUDOKU_KEY_AUTO && sudoku_key_is_public_point(raw, raw_len))) {
        if (raw_len != 32) {
            return -1;
        }
        sudoku_hex_encode(raw, 32, cfg->public_key_hex);
        return 0;
    }

    if (cfg->key_kind == SUDOKU_KEY_PRIVATE64 || raw_len == 64) {
        if (sudoku_public_key_from_private(raw, 64, public_key) != 0) {
            return -1;
        }
        memcpy(cfg->private_key, raw, 64);
        cfg->private_key_len = 64;
        sudoku_hex_encode(public_key, 32, cfg->public_key_hex);
        return 0;
    }

    if (cfg->key_kind == SUDOKU_KEY_PRIVATE32 || raw_len == 32) {
        if (sudoku_public_key_from_private(raw, 32, public_key) != 0) {
            return -1;
        }
        memcpy(cfg->private_key, raw, 32);
        cfg->private_key_len = 32;
        sudoku_hex_encode(public_key, 32, cfg->public_key_hex);
        return 0;
    }

    return -1;
}

void sudoku_outbound_config_init(sudoku_outbound_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->key_kind = SUDOKU_KEY_AUTO;
    strcpy(cfg->aead_method, "chacha20-poly1305");
    strcpy(cfg->ascii_mode, "prefer_entropy");
    cfg->padding_min = 5;
    cfg->padding_max = 15;
    cfg->enable_pure_downlink = 0;
    cfg->httpmask_disable = 1;
    strcpy(cfg->httpmask_mode, "legacy");
    strcpy(cfg->httpmask_multiplex, "off");
}

int sudoku_outbound_config_finalize(sudoku_outbound_config_t *cfg) {
    size_t i;
    if (!cfg->server_host[0] || !cfg->server_port || !cfg->key_hex[0]) {
        return -1;
    }
    if (cfg->custom_tables_count > SUDOKU_MAX_CUSTOM_TABLES) {
        return -1;
    }
    for (i = 0; i < cfg->custom_tables_count; ++i) {
        if (strlen(cfg->custom_tables[i]) > SUDOKU_MAX_CUSTOM_TABLE_LEN) {
            return -1;
        }
    }
    return sudoku_normalize_key(cfg);
}

static int sudoku_random_index(size_t count, size_t *out_index) {
    uint8_t b[2];
    if (!out_index || count == 0) return -1;
#if SUDOKU_APPLE_SWIFT_BACKEND
    arc4random_buf(b, sizeof(b));
#else
    if (RAND_bytes(b, sizeof(b)) != 1) return -1;
#endif
    *out_index = ((((size_t)b[0]) << 8) | b[1]) % count;
    return 0;
}

static int sudoku_ascii_mode_tokens(
    const char *ascii_mode,
    const char **out_uplink,
    const char **out_downlink
) {
    sudoku_ascii_mode_t mode;
    if (sudoku_parse_ascii_mode(ascii_mode, &mode) != 0) return -1;
    if (out_uplink) *out_uplink = mode.uplink_token;
    if (out_downlink) *out_downlink = mode.downlink_token;
    return 0;
}

static int sudoku_pick_client_tables(
    const sudoku_outbound_config_t *cfg,
    sudoku_table_pair_t *out_tables
) {
    const char *uplink_token = NULL;
    const char *downlink_token = NULL;
    const char *patterns[SUDOKU_MAX_CUSTOM_TABLES];
    size_t pattern_count = 0;
    size_t selected = 0;
    const char *pattern = "";
    const char *custom_uplink = "";
    const char *custom_downlink = "";
    size_t i;

    if (!cfg || !out_tables) return -1;
    if (sudoku_ascii_mode_tokens(cfg->ascii_mode, &uplink_token, &downlink_token) != 0) {
        return -1;
    }

    if (cfg->custom_tables_count > 0) {
        for (i = 0; i < cfg->custom_tables_count && i < SUDOKU_MAX_CUSTOM_TABLES; ++i) {
            patterns[pattern_count++] = cfg->custom_tables[i];
        }
    } else {
        patterns[pattern_count++] = "";
    }

    if (pattern_count > 1 && strcmp(uplink_token, "entropy") != 0 && strcmp(downlink_token, "entropy") != 0) {
        pattern_count = 1;
    }
    if (pattern_count > 1 && sudoku_random_index(pattern_count, &selected) != 0) {
        return -1;
    }
    pattern = patterns[selected];
    if (!strcmp(uplink_token, "entropy")) custom_uplink = pattern;
    if (!strcmp(downlink_token, "entropy")) custom_downlink = pattern;
    return sudoku_table_pair_init(out_tables, sudoku_seed_key_hex(cfg), cfg->ascii_mode, custom_uplink, custom_downlink);
}

static sudoku_aead_kind_t sudoku_parse_aead(const char *method) {
    if (!strcmp(method, "aes-128-gcm")) return SUDOKU_AEAD_AES128GCM;
    if (!strcmp(method, "none")) return SUDOKU_AEAD_NONE;
    return SUDOKU_AEAD_CHACHA20;
}

static int sudoku_random_nonzero_u32(uint32_t *out) {
    do {
#if SUDOKU_APPLE_SWIFT_BACKEND
        arc4random_buf(out, sizeof(*out));
#else
        if (RAND_bytes((unsigned char *)out, sizeof(*out)) != 1) return -1;
#endif
    } while (*out == 0 || *out == UINT32_MAX);
    return 0;
}

static int sudoku_random_nonzero_u64(uint64_t *out) {
    do {
#if SUDOKU_APPLE_SWIFT_BACKEND
        arc4random_buf(out, sizeof(*out));
#else
        if (RAND_bytes((unsigned char *)out, sizeof(*out)) != 1) return -1;
#endif
    } while (*out == 0 || *out == UINT64_MAX);
    return 0;
}

static ssize_t sudoku_socket_send(sudoku_transport_t *tr, const void *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n;
        pthread_mutex_lock(&tr->write_mu);
#if !SUDOKU_APPLE_SWIFT_BACKEND
        if (tr->ssl) n = SSL_write(tr->ssl, (const uint8_t *)buf + sent, (int)(len - sent));
        else n = send(tr->fd, (const uint8_t *)buf + sent, len - sent, 0);
#else
        n = send(tr->fd, (const uint8_t *)buf + sent, len - sent, 0);
#endif
        pthread_mutex_unlock(&tr->write_mu);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return (ssize_t)sent;
}

static ssize_t sudoku_socket_recv_some(sudoku_transport_t *tr, void *buf, size_t len) {
    pthread_mutex_lock(&tr->read_mu);
#if !SUDOKU_APPLE_SWIFT_BACKEND
    if (tr->ssl) {
        ssize_t n = SSL_read(tr->ssl, buf, (int)len);
        pthread_mutex_unlock(&tr->read_mu);
        return n;
    } else {
#endif
        ssize_t n;
        do {
            n = recv(tr->fd, buf, len, 0);
        } while (n < 0 && errno == EINTR);
        pthread_mutex_unlock(&tr->read_mu);
        return n;
#if !SUDOKU_APPLE_SWIFT_BACKEND
    }
#endif
}

static int sudoku_transport_read_exact_raw(sudoku_transport_t *tr, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = sudoku_socket_recv_some(tr, p + got, len - got);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

static int sudoku_base64_encode(const uint8_t *src, size_t src_len, char *out, size_t out_cap) {
#if SUDOKU_APPLE_SWIFT_BACKEND
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t need = ((src_len + 2) / 3) * 4;
    size_t i = 0;
    size_t j = 0;
    if (need + 1 > out_cap) return -1;
    while (i < src_len) {
        uint32_t v = ((uint32_t)src[i]) << 16;
        int rem = (int)(src_len - i);
        if (rem > 1) v |= ((uint32_t)src[i + 1]) << 8;
        if (rem > 2) v |= src[i + 2];
        out[j++] = alphabet[(v >> 18) & 0x3f];
        out[j++] = alphabet[(v >> 12) & 0x3f];
        out[j++] = rem > 1 ? alphabet[(v >> 6) & 0x3f] : '=';
        out[j++] = rem > 2 ? alphabet[v & 0x3f] : '=';
        i += rem >= 3 ? 3 : (size_t)rem;
    }
    out[j] = '\0';
    return (int)j;
#else
    int n = EVP_EncodeBlock((unsigned char *)out, src, (int)src_len);
    if (n <= 0 || (size_t)n + 1 > out_cap) return -1;
    out[n] = '\0';
    return n;
#endif
}

static int sudoku_base64url_encode(const uint8_t *src, size_t src_len, char *out, size_t out_cap) {
    int n;
    size_t i;
    n = sudoku_base64_encode(src, src_len, out, out_cap);
    if (n < 0) return -1;
    while (n > 0 && out[n - 1] == '=') {
        out[--n] = '\0';
    }
    for (i = 0; i < (size_t)n; ++i) {
        if (out[i] == '+') out[i] = '-';
        else if (out[i] == '/') out[i] = '_';
    }
    return n;
}

static void sudoku_apply_path_root(char *dst, size_t dst_cap, const char *root, const char *path) {
    char clean[96];
    size_t n = 0;
    clean[0] = '\0';
    if (root) {
        for (; *root; ++root) {
            if (*root == '/') continue;
            if ((*root >= 'a' && *root <= 'z') || (*root >= 'A' && *root <= 'Z') ||
                (*root >= '0' && *root <= '9') || *root == '_' || *root == '-') {
                if (n + 1 < sizeof(clean)) clean[n++] = *root;
            } else {
                n = 0;
                break;
            }
        }
    }
    clean[n] = '\0';
    if (n == 0) {
        snprintf(dst, dst_cap, "%s", path);
    } else {
        snprintf(dst, dst_cap, "/%s%s", clean, path);
    }
}

static void sudoku_httpmask_auth_token(
    const char *auth_key,
    const char *mode,
    const char *method,
    const char *path,
    char out[128]
) {
    uint8_t key[32];
    uint8_t full[32];
    uint8_t ts_sig[24];
    uint64_t ts = (uint64_t)time(NULL);
    static const uint8_t zero_sep = 0;
    sudoku_bytespan_t mac_parts[7];

    {
#if SUDOKU_APPLE_SWIFT_BACKEND
        CC_SHA256_CTX md;
        CC_SHA256_Init(&md);
        CC_SHA256_Update(&md, "sudoku-httpmask-auth-v1:", 24);
        CC_SHA256_Update(&md, auth_key, (CC_LONG)strlen(auth_key));
        CC_SHA256_Final(key, &md);
#else
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        if (!md) {
            memset(key, 0, sizeof(key));
        } else {
            if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1 ||
                EVP_DigestUpdate(md, "sudoku-httpmask-auth-v1:", 24) != 1 ||
                EVP_DigestUpdate(md, auth_key, strlen(auth_key)) != 1 ||
                EVP_DigestFinal_ex(md, key, NULL) != 1) {
                memset(key, 0, sizeof(key));
            }
            EVP_MD_CTX_free(md);
        }
#endif
    }

    ts_sig[0] = (uint8_t)(ts >> 56);
    ts_sig[1] = (uint8_t)(ts >> 48);
    ts_sig[2] = (uint8_t)(ts >> 40);
    ts_sig[3] = (uint8_t)(ts >> 32);
    ts_sig[4] = (uint8_t)(ts >> 24);
    ts_sig[5] = (uint8_t)(ts >> 16);
    ts_sig[6] = (uint8_t)(ts >> 8);
    ts_sig[7] = (uint8_t)ts;

    mac_parts[0].data = (const uint8_t *)mode;
    mac_parts[0].len = strlen(mode);
    mac_parts[1].data = &zero_sep;
    mac_parts[1].len = 1;
    mac_parts[2].data = (const uint8_t *)method;
    mac_parts[2].len = strlen(method);
    mac_parts[3].data = &zero_sep;
    mac_parts[3].len = 1;
    mac_parts[4].data = (const uint8_t *)path;
    mac_parts[4].len = strlen(path);
    mac_parts[5].data = &zero_sep;
    mac_parts[5].len = 1;
    mac_parts[6].data = ts_sig;
    mac_parts[6].len = 8;
    if (sudoku_hmac_sha256_parts(key, sizeof(key), mac_parts, 7, full) != 0) {
        memset(full, 0, sizeof(full));
    }

    memcpy(ts_sig + 8, full, 16);
    sudoku_base64url_encode(ts_sig, sizeof(ts_sig), out, 128);
}

static int sudoku_tcp_connect_ex(
    const sudoku_outbound_config_t *cfg,
    const char *host,
    uint16_t port,
    int use_tls,
    const char *server_name
) {
    char port_s[16];
    struct addrinfo hints;
    struct addrinfo *res = NULL, *rp = NULL;
    int fd = -1;
    if (cfg && cfg->swift_socket_factory_ctx) {
#if SUDOKU_APPLE_SWIFT_BACKEND
        fd = sudoku_swift_socket_factory_open_ex(
            cfg->swift_socket_factory_ctx,
            host,
            port,
            use_tls ? 1 : 0,
            server_name
        );
#else
        fd = sudoku_swift_socket_factory_open(cfg->swift_socket_factory_ctx, host, port);
#endif
        if (fd >= 0) {
            return fd;
        }
    }
#if SUDOKU_APPLE_SWIFT_BACKEND
    if (use_tls) return -1;
#else
    (void)use_tls;
    (void)server_name;
#endif
    snprintf(port_s, sizeof(port_s), "%u", (unsigned)port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(host, port_s, &hints, &res) != 0) {
        return -1;
    }
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        sudoku_set_socket_common_opts(fd);
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static sudoku_transport_t *sudoku_transport_new(int fd) {
    sudoku_transport_t *tr = (sudoku_transport_t *)calloc(1, sizeof(*tr));
    if (!tr) return NULL;
    tr->fd = fd;
    tr->kind = SUDOKU_TRANSPORT_RAW;
    pthread_mutex_init(&tr->read_mu, NULL);
    pthread_mutex_init(&tr->write_mu, NULL);
    return tr;
}

static int sudoku_random_splitmix64_seed(int64_t *out_seed) {
    uint64_t seed = 0;
#if SUDOKU_APPLE_SWIFT_BACKEND
    arc4random_buf(&seed, sizeof(seed));
#else
    if (RAND_bytes((unsigned char *)&seed, sizeof(seed)) != 1) {
        seed = (uint64_t)time(NULL) ^ (uint64_t)(uintptr_t)out_seed;
    }
#endif
    *out_seed = (int64_t)seed;
    return 0;
}

static int sudoku_transport_enable_obfs(
    sudoku_transport_t *tr,
    const sudoku_table_pair_t *tables,
    int padding_min,
    int padding_max,
    int pure_downlink
) {
    int64_t seed = 0;
    if (!tr || !tables) return -1;
    if (sudoku_random_splitmix64_seed(&seed) != 0) return -1;
    tr->uplink_table = &tables->uplink;
    tr->downlink_table = &tables->downlink;
    tr->pure_downlink = pure_downlink ? 1 : 0;
    sudoku_splitmix64_seed(&tr->rng, seed);
    tr->padding_threshold = sudoku_pick_padding_threshold(&tr->rng, padding_min, padding_max);
    sudoku_decoder_init(&tr->pure_decoder);
    sudoku_packed_decoder_init(&tr->packed_decoder, &tables->downlink);
    tr->plain_len = 0;
    tr->plain_off = 0;
    tr->obfs_enabled = 1;
    return 0;
}

static void sudoku_transport_close(sudoku_transport_t *tr) {
    if (!tr) return;
    if (tr->httpmask) {
        sudoku_httpmask_state_t *state = tr->httpmask;
        sudoku_httpmask_mark_closed(state, 0);
        sudoku_httpmask_interrupt_active(state);
        if (state->token[0]) (void)sudoku_httpmask_best_effort_post(state, state->close_path);
        if (state->pull_started) pthread_join(state->pull_thread, NULL);
        if (state->push_started) pthread_join(state->push_thread, NULL);
        sudoku_byte_chunk_free_all(state->rx_head);
        sudoku_byte_chunk_free_all(state->tx_head);
        pthread_cond_destroy(&state->tx_cond);
        pthread_cond_destroy(&state->rx_cond);
        pthread_mutex_destroy(&state->req_mu);
        pthread_mutex_destroy(&state->mu);
        free(state);
        tr->httpmask = NULL;
    }
#if !SUDOKU_APPLE_SWIFT_BACKEND
    if (tr->ssl) {
        SSL_shutdown(tr->ssl);
        SSL_free(tr->ssl);
    }
    if (tr->ssl_ctx) SSL_CTX_free(tr->ssl_ctx);
#endif
    if (tr->fd >= 0) close(tr->fd);
    pthread_mutex_destroy(&tr->read_mu);
    pthread_mutex_destroy(&tr->write_mu);
    free(tr);
}

static void sudoku_transport_interrupt(sudoku_transport_t *tr) {
    if (!tr) return;
    if (tr->httpmask) {
        sudoku_httpmask_mark_closed(tr->httpmask, 1);
        sudoku_httpmask_interrupt_active(tr->httpmask);
    }
    if (tr->fd >= 0) {
        shutdown(tr->fd, SHUT_RDWR);
    }
}

static int sudoku_transport_enable_tls(sudoku_transport_t *tr, const char *server_name) {
#if SUDOKU_APPLE_SWIFT_BACKEND
    (void)tr;
    (void)server_name;
    return 0;
#else
    SSL_CTX *ctx;
    SSL *ssl;
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return -1;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return -1;
    }
    SSL_set_fd(ssl, tr->fd);
    SSL_set_tlsext_host_name(ssl, server_name);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }
    tr->ssl_ctx = ctx;
    tr->ssl = ssl;
    return 0;
#endif
}

static void sudoku_byte_chunk_free_all(sudoku_byte_chunk_t *chunk) {
    while (chunk) {
        sudoku_byte_chunk_t *next = chunk->next;
        free(chunk->data);
        free(chunk);
        chunk = next;
    }
}

static const char *sudoku_httpmask_mode_name(sudoku_transport_kind_t kind) {
    if (kind == SUDOKU_TRANSPORT_HTTP_POLL) return "poll";
    return "stream";
}

static void sudoku_httpmask_mark_closed(sudoku_httpmask_state_t *state, int fatal) {
    if (!state) return;
    pthread_mutex_lock(&state->mu);
    state->closed = 1;
    if (fatal) state->fatal = 1;
    pthread_cond_broadcast(&state->rx_cond);
    pthread_cond_broadcast(&state->tx_cond);
    pthread_mutex_unlock(&state->mu);
}

static void sudoku_http_conn_close(sudoku_http_conn_t *conn) {
    if (!conn) return;
#if !SUDOKU_APPLE_SWIFT_BACKEND
    if (conn->ssl) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }
    if (conn->ssl_ctx) SSL_CTX_free(conn->ssl_ctx);
#endif
    if (conn->fd >= 0) close(conn->fd);
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;
}

static void sudoku_http_conn_interrupt(sudoku_http_conn_t *conn) {
    if (!conn) return;
    if (conn->fd >= 0) shutdown(conn->fd, SHUT_RDWR);
}

static int sudoku_http_conn_open(const sudoku_outbound_config_t *cfg, sudoku_http_conn_t *conn) {
    struct timeval tv;
#if !SUDOKU_APPLE_SWIFT_BACKEND
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
#endif
    const char *server_name;
    if (!cfg || !conn) return -1;
    memset(conn, 0, sizeof(*conn));
    server_name = cfg->httpmask_host[0] ? cfg->httpmask_host : cfg->server_host;
    conn->fd = sudoku_tcp_connect_ex(cfg, cfg->server_host, cfg->server_port, cfg->httpmask_tls, server_name);
    if (conn->fd < 0) return -1;
    sudoku_set_socket_common_opts(conn->fd);
    tv.tv_sec = 70;
    tv.tv_usec = 0;
    setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(conn->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (!cfg->httpmask_tls) return 0;
#if SUDOKU_APPLE_SWIFT_BACKEND
    return 0;
#else
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) goto fail;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    ssl = SSL_new(ctx);
    if (!ssl) goto fail;
    SSL_set_fd(ssl, conn->fd);
    SSL_set_tlsext_host_name(ssl, (char *)(cfg->httpmask_host[0] ? cfg->httpmask_host : cfg->server_host));
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        goto fail_ctx;
    }
    conn->ssl_ctx = ctx;
    conn->ssl = ssl;
    return 0;
fail:
    if (ctx) SSL_CTX_free(ctx);
    if (conn->fd >= 0) close(conn->fd);
    conn->fd = -1;
    return -1;
fail_ctx:
    SSL_CTX_free(ctx);
    if (conn->fd >= 0) close(conn->fd);
    conn->fd = -1;
    return -1;
#endif
}

static ssize_t sudoku_http_conn_send_all(sudoku_http_conn_t *conn, const void *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n;
#if !SUDOKU_APPLE_SWIFT_BACKEND
        if (conn->ssl) n = SSL_write(conn->ssl, (const uint8_t *)buf + sent, (int)(len - sent));
        else
#endif
        n = send(conn->fd, (const uint8_t *)buf + sent, len - sent, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return (ssize_t)sent;
}

static ssize_t sudoku_http_conn_recv_some(sudoku_http_conn_t *conn, void *buf, size_t len) {
    for (;;) {
        ssize_t n;
#if !SUDOKU_APPLE_SWIFT_BACKEND
        if (conn->ssl) n = SSL_read(conn->ssl, buf, (int)len);
        else
#endif
        n = recv(conn->fd, buf, len, 0);
        if (n < 0 && errno == EINTR) continue;
        return n;
    }
}

static ssize_t sudoku_http_conn_read_some_buffered(sudoku_http_conn_t *conn, void *buf, size_t len) {
    uint8_t *out = (uint8_t *)buf;
    if (!conn || !buf || len == 0) return -1;
    if (conn->read_off < conn->read_len) {
        size_t n = conn->read_len - conn->read_off;
        if (n > len) n = len;
        memcpy(out, conn->read_buf + conn->read_off, n);
        conn->read_off += n;
        if (conn->read_off == conn->read_len) conn->read_off = conn->read_len = 0;
        return (ssize_t)n;
    }
    return sudoku_http_conn_recv_some(conn, buf, len);
}

static int sudoku_http_conn_read_exact(sudoku_http_conn_t *conn, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = sudoku_http_conn_read_some_buffered(conn, p + got, len - got);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

static int sudoku_http_conn_read_byte(sudoku_http_conn_t *conn, uint8_t *out) {
    if (!conn || !out) return -1;
    if (conn->read_off == conn->read_len) {
        ssize_t n = sudoku_http_conn_recv_some(conn, conn->read_buf, sizeof(conn->read_buf));
        if (n <= 0) return -1;
        conn->read_off = 0;
        conn->read_len = (size_t)n;
    }
    *out = conn->read_buf[conn->read_off++];
    return 0;
}

static int sudoku_http_conn_read_line(sudoku_http_conn_t *conn, char *line, size_t line_cap) {
    size_t off = 0;
    uint8_t b = 0;
    int saw_cr = 0;
    if (!conn || !line || line_cap == 0) return -1;
    while (1) {
        if (sudoku_http_conn_read_byte(conn, &b) != 0) return -1;
        if (b == '\r') {
            saw_cr = 1;
            continue;
        }
        if (b == '\n') {
            line[off] = '\0';
            return 0;
        }
        if (off + 1 >= line_cap) return -1;
        if (saw_cr) {
            line[off++] = '\r';
            saw_cr = 0;
        }
        line[off++] = (char)b;
    }
}

static void sudoku_httpmask_host_header(
    const sudoku_outbound_config_t *cfg,
    char *host_header,
    size_t host_header_cap
) {
    const char *host = cfg->httpmask_host[0] ? cfg->httpmask_host : cfg->server_host;
    if ((cfg->httpmask_tls && cfg->server_port == 443) || (!cfg->httpmask_tls && cfg->server_port == 80)) {
        snprintf(host_header, host_header_cap, "%s", host);
    } else {
        snprintf(host_header, host_header_cap, "%s:%u", host, (unsigned)cfg->server_port);
    }
}

static void sudoku_httpmask_append_auth_query(
    char *dst,
    size_t dst_cap,
    const char *path_with_query,
    const char *auth_token
) {
    if (auth_token && auth_token[0]) {
        snprintf(dst, dst_cap, "%s%sauth=%s", path_with_query, strchr(path_with_query, '?') ? "&" : "?", auth_token);
    } else {
        snprintf(dst, dst_cap, "%s", path_with_query);
    }
}

static int sudoku_http_read_response_headers(
    sudoku_http_conn_t *conn,
    sudoku_http_body_reader_t *body
) {
    char line[1024];
    int status = 0;
    int chunked = 0;
    size_t content_length = 0;
    int have_length = 0;
    if (sudoku_http_conn_read_line(conn, line, sizeof(line)) != 0) return -1;
    if (sscanf(line, "HTTP/%*s %d", &status) != 1) return -1;
    while (1) {
        char key[256];
        char value[768];
        if (sudoku_http_conn_read_line(conn, line, sizeof(line)) != 0) return -1;
        if (line[0] == '\0') break;
        if (sscanf(line, "%255[^:]: %767[^\r\n]", key, value) == 2) {
            if (!strcasecmp(key, "Transfer-Encoding") && strstr(value, "chunked")) {
                chunked = 1;
            } else if (!strcasecmp(key, "Content-Length")) {
                content_length = (size_t)strtoull(value, NULL, 10);
                have_length = 1;
            }
        }
    }
    memset(body, 0, sizeof(*body));
    body->conn = conn;
    body->status_code = status;
    body->chunked = chunked;
    body->close_delimited = (!chunked && !have_length) ? 1 : 0;
    body->content_remaining = content_length;
    return 0;
}

static int sudoku_http_body_read_some(sudoku_http_body_reader_t *body, uint8_t *buf, size_t buf_cap, size_t *out_len) {
    if (!body || !buf || !out_len) return -1;
    *out_len = 0;
    if (body->done) return 0;
    if (body->chunked) {
        while (body->chunk_remaining == 0) {
            char line[256];
            char *semi;
            unsigned long long chunk_len;
            if (sudoku_http_conn_read_line(body->conn, line, sizeof(line)) != 0) return -1;
            semi = strchr(line, ';');
            if (semi) *semi = '\0';
            chunk_len = strtoull(line, NULL, 16);
            if (chunk_len == 0) {
                do {
                    if (sudoku_http_conn_read_line(body->conn, line, sizeof(line)) != 0) return -1;
                } while (line[0] != '\0');
                body->done = 1;
                return 0;
            }
            body->chunk_remaining = (size_t)chunk_len;
        }
        if (buf_cap > body->chunk_remaining) buf_cap = body->chunk_remaining;
        if (sudoku_http_conn_read_exact(body->conn, buf, buf_cap) != 0) return -1;
        body->chunk_remaining -= buf_cap;
        *out_len = buf_cap;
        if (body->chunk_remaining == 0) {
            uint8_t crlf[2];
            if (sudoku_http_conn_read_exact(body->conn, crlf, 2) != 0) return -1;
        }
        return 0;
    }
    if (!body->close_delimited) {
        if (body->content_remaining == 0) {
            body->done = 1;
            return 0;
        }
        if (buf_cap > body->content_remaining) buf_cap = body->content_remaining;
        if (sudoku_http_conn_read_exact(body->conn, buf, buf_cap) != 0) return -1;
        body->content_remaining -= buf_cap;
        *out_len = buf_cap;
        if (body->content_remaining == 0) body->done = 1;
        return 0;
    }
    {
        ssize_t n = sudoku_http_conn_read_some_buffered(body->conn, buf, buf_cap);
        if (n < 0) return -1;
        if (n == 0) {
            body->done = 1;
            return 0;
        }
        *out_len = (size_t)n;
        return 0;
    }
}

static int sudoku_http_read_body_limit(
    sudoku_http_body_reader_t *body,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len
) {
    size_t total = 0;
    while (total < out_cap) {
        size_t n = 0;
        if (sudoku_http_body_read_some(body, out + total, out_cap - total, &n) != 0) return -1;
        if (n == 0) break;
        total += n;
    }
    if (out_len) *out_len = total;
    return 0;
}

static int sudoku_base64_decode(const char *src, uint8_t *out, size_t out_cap, size_t *out_len) {
#if SUDOKU_APPLE_SWIFT_BACKEND
    size_t src_len;
    size_t i = 0;
    size_t j = 0;
    int vals[4];
    int val_count = 0;
    if (!src || !out || !out_len) return -1;
    src_len = strlen(src);
    *out_len = 0;
    while (i < src_len) {
        unsigned char ch = (unsigned char)src[i++];
        int v;
        if (ch >= 'A' && ch <= 'Z') v = ch - 'A';
        else if (ch >= 'a' && ch <= 'z') v = ch - 'a' + 26;
        else if (ch >= '0' && ch <= '9') v = ch - '0' + 52;
        else if (ch == '+') v = 62;
        else if (ch == '/') v = 63;
        else if (ch == '=') v = -2;
        else if (ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t') continue;
        else return -1;
        vals[val_count++] = v;
        if (val_count == 4) {
            uint32_t triple;
            if (vals[0] < 0 || vals[1] < 0) return -1;
            triple = ((uint32_t)vals[0] << 18) | ((uint32_t)vals[1] << 12);
            if (vals[2] >= 0) triple |= (uint32_t)vals[2] << 6;
            if (vals[3] >= 0) triple |= (uint32_t)vals[3];
            if (j >= out_cap) return -1;
            out[j++] = (uint8_t)(triple >> 16);
            if (vals[2] != -2) {
                if (j >= out_cap) return -1;
                out[j++] = (uint8_t)(triple >> 8);
            }
            if (vals[3] != -2) {
                if (j >= out_cap) return -1;
                out[j++] = (uint8_t)triple;
            }
            val_count = 0;
        }
    }
    if (val_count != 0) return -1;
    *out_len = j;
    return 0;
#else
    int n;
    size_t src_len = strlen(src);
    size_t pad = 0;
    if (!src || !out || !out_len) return -1;
    if (src_len == 0) {
        *out_len = 0;
        return 0;
    }
    if (src[src_len - 1] == '=') pad++;
    if (src_len > 1 && src[src_len - 2] == '=') pad++;
    if (((src_len / 4) * 3) < pad) return -1;
    if (((src_len / 4) * 3) - pad > out_cap) return -1;
    n = EVP_DecodeBlock(out, (const unsigned char *)src, (int)src_len);
    if (n < 0 || (size_t)n < pad) return -1;
    *out_len = (size_t)n - pad;
    return 0;
#endif
}

static int sudoku_http_request_open(
    const sudoku_httpmask_state_t *state,
    const char *method,
    const char *request_path,
    const char *auth_path,
    const char *content_type,
    const uint8_t *body,
    size_t body_len,
    sudoku_http_conn_t **out_conn,
    sudoku_http_body_reader_t *out_body
) {
    sudoku_http_conn_t *conn = NULL;
    char auth_token[128] = "";
    char req_path[768];
    char req[2048];
    const char *mode = sudoku_httpmask_mode_name(state->mode);
    int req_len;
    if (!state || !method || !request_path || !auth_path || !out_conn || !out_body) return -1;
    conn = (sudoku_http_conn_t *)calloc(1, sizeof(*conn));
    if (!conn) return -1;
    conn->fd = -1;
    if (sudoku_http_conn_open(&state->cfg, conn) != 0) goto fail;
    sudoku_httpmask_auth_token(sudoku_seed_key_hex(&state->cfg), mode, method, auth_path, auth_token);
    sudoku_httpmask_append_auth_query(req_path, sizeof(req_path), request_path, auth_token);
    req_len = snprintf(req, sizeof(req),
                       "%s %s HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "User-Agent: Mozilla/5.0\r\n"
                       "Accept: */*\r\n"
                       "Cache-Control: no-cache\r\n"
                       "Pragma: no-cache\r\n"
                       "Connection: close\r\n"
                       "X-Sudoku-Tunnel: %s\r\n"
                       "Authorization: Bearer %s\r\n"
                       "%s"
                       "Content-Length: %zu\r\n"
                       "\r\n",
                       method,
                       req_path,
                       state->header_host,
                       mode,
                       auth_token,
                       content_type ? content_type : "",
                       body_len);
    if (req_len < 0 || (size_t)req_len >= sizeof(req)) goto fail;
    if (sudoku_http_conn_send_all(conn, req, (size_t)req_len) < 0) goto fail;
    if (body_len && sudoku_http_conn_send_all(conn, body, body_len) < 0) goto fail;
    if (sudoku_http_read_response_headers(conn, out_body) != 0) goto fail;
    *out_conn = conn;
    return 0;
fail:
    sudoku_http_conn_close(conn);
    free(conn);
    return -1;
}

static int sudoku_httpmask_parse_authorize(
    const uint8_t *body,
    size_t body_len,
    char *token,
    size_t token_cap
) {
    char line[512];
    size_t off = 0;
    if (!body || !token || token_cap == 0) return -1;
    token[0] = '\0';
    while (off < body_len) {
        size_t line_len = 0;
        while (off + line_len < body_len && body[off + line_len] != '\n') line_len++;
        if (line_len >= sizeof(line)) line_len = sizeof(line) - 1;
        memcpy(line, body + off, line_len);
        line[line_len] = '\0';
        while (line_len > 0 && (line[line_len - 1] == '\r' || line[line_len - 1] == '\n')) line[--line_len] = '\0';
        {
            const char *prefix = strstr(line, "token=");
            if (prefix) {
                size_t i = 0;
                prefix += 6;
                while (prefix[i] &&
                       ((prefix[i] >= 'a' && prefix[i] <= 'z') ||
                        (prefix[i] >= 'A' && prefix[i] <= 'Z') ||
                        (prefix[i] >= '0' && prefix[i] <= '9') ||
                        prefix[i] == '-' || prefix[i] == '_')) {
                    if (i + 1 < token_cap) token[i] = prefix[i];
                    i++;
                }
                if (i >= token_cap) return -1;
                token[i] = '\0';
                return token[0] ? 0 : -1;
            }
        }
        off += line_len;
        while (off < body_len && body[off] != '\n') off++;
        if (off < body_len) off++;
    }
    return -1;
}

static int sudoku_httpmask_authorize(sudoku_httpmask_state_t *state) {
    sudoku_http_conn_t *conn = NULL;
    sudoku_http_body_reader_t body;
    uint8_t resp[4096];
    size_t resp_len = 0;
    char stream_path[256];
    char upload_path[256];
    if (sudoku_http_request_open(state, "GET", state->session_path, "/session", NULL, NULL, 0, &conn, &body) != 0) {
        return -1;
    }
    if (body.status_code != 200) goto fail;
    if (sudoku_http_read_body_limit(&body, resp, sizeof(resp), &resp_len) != 0) goto fail;
    if (sudoku_httpmask_parse_authorize(resp, resp_len, state->token, sizeof(state->token)) != 0) goto fail;
    sudoku_apply_path_root(stream_path, sizeof(stream_path), state->cfg.httpmask_path_root, "/stream");
    sudoku_apply_path_root(upload_path, sizeof(upload_path), state->cfg.httpmask_path_root, "/api/v1/upload");
    snprintf(state->pull_path, sizeof(state->pull_path), "%s?token=%s", stream_path, state->token);
    snprintf(state->push_path, sizeof(state->push_path), "%s?token=%s", upload_path, state->token);
    snprintf(state->fin_path, sizeof(state->fin_path), "%s&fin=1", state->push_path);
    snprintf(state->close_path, sizeof(state->close_path), "%s&close=1", state->push_path);
    sudoku_http_conn_close(conn);
    free(conn);
    return 0;
fail:
    sudoku_http_conn_close(conn);
    free(conn);
    return -1;
}

static int sudoku_httpmask_enqueue(
    sudoku_byte_chunk_t **head,
    sudoku_byte_chunk_t **tail,
    const uint8_t *buf,
    size_t len
) {
    sudoku_byte_chunk_t *chunk;
    if ((!buf && len) || !head || !tail) return -1;
    chunk = (sudoku_byte_chunk_t *)calloc(1, sizeof(*chunk));
    if (!chunk) return -1;
    chunk->data = (uint8_t *)malloc(len ? len : 1);
    if (!chunk->data) {
        free(chunk);
        return -1;
    }
    if (len) memcpy(chunk->data, buf, len);
    chunk->len = len;
    if (*tail) (*tail)->next = chunk;
    else *head = chunk;
    *tail = chunk;
    return 0;
}

static size_t sudoku_httpmask_pop_bytes(
    sudoku_byte_chunk_t **head,
    sudoku_byte_chunk_t **tail,
    uint8_t *buf,
    size_t cap
) {
    size_t total = 0;
    while (*head && total < cap) {
        sudoku_byte_chunk_t *chunk = *head;
        size_t take = chunk->len - chunk->off;
        if (take > cap - total) take = cap - total;
        memcpy(buf + total, chunk->data + chunk->off, take);
        chunk->off += take;
        total += take;
        if (chunk->off == chunk->len) {
            *head = chunk->next;
            if (!*head) *tail = NULL;
            free(chunk->data);
            free(chunk);
        }
    }
    return total;
}

static int sudoku_httpmask_queue_rx(sudoku_httpmask_state_t *state, const uint8_t *buf, size_t len) {
    int rc;
    pthread_mutex_lock(&state->mu);
    rc = state->closed ? -1 : sudoku_httpmask_enqueue(&state->rx_head, &state->rx_tail, buf, len);
    if (rc == 0) pthread_cond_signal(&state->rx_cond);
    pthread_mutex_unlock(&state->mu);
    return rc;
}

static int sudoku_httpmask_queue_tx(sudoku_httpmask_state_t *state, const uint8_t *buf, size_t len) {
    int rc;
    pthread_mutex_lock(&state->mu);
    rc = state->closed ? -1 : sudoku_httpmask_enqueue(&state->tx_head, &state->tx_tail, buf, len);
    if (rc == 0) pthread_cond_signal(&state->tx_cond);
    pthread_mutex_unlock(&state->mu);
    return rc;
}

static ssize_t sudoku_httpmask_recv_wire(sudoku_httpmask_state_t *state, uint8_t *buf, size_t len) {
    ssize_t out = -1;
    if (!state || !buf || len == 0) return -1;
    pthread_mutex_lock(&state->mu);
    while (!state->rx_head && !state->closed) {
        pthread_cond_wait(&state->rx_cond, &state->mu);
    }
    if (state->rx_head) {
        out = (ssize_t)sudoku_httpmask_pop_bytes(&state->rx_head, &state->rx_tail, buf, len);
    }
    pthread_mutex_unlock(&state->mu);
    return out;
}

static int sudoku_httpmask_wait_tx(sudoku_httpmask_state_t *state, int timeout_ms) {
    int rc = 0;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000L;
    }
    while (!state->tx_head && !state->closed && rc == 0) {
        rc = pthread_cond_timedwait(&state->tx_cond, &state->mu, &ts);
    }
    return rc;
}

static size_t sudoku_httpmask_take_tx(sudoku_httpmask_state_t *state, uint8_t *buf, size_t cap, int timeout_ms, int *closed) {
    size_t total = 0;
    if (!state || !buf || !closed) return 0;
    *closed = 0;
    pthread_mutex_lock(&state->mu);
    if (!state->tx_head && !state->closed && timeout_ms >= 0) {
        (void)sudoku_httpmask_wait_tx(state, timeout_ms);
    }
    total = sudoku_httpmask_pop_bytes(&state->tx_head, &state->tx_tail, buf, cap);
    *closed = state->closed && !state->tx_head;
    pthread_mutex_unlock(&state->mu);
    return total;
}

static void sudoku_httpmask_set_active(
    sudoku_httpmask_state_t *state,
    int pull_side,
    sudoku_http_conn_t *conn
) {
    pthread_mutex_lock(&state->req_mu);
    if (pull_side) state->active_pull = conn;
    else state->active_push = conn;
    pthread_mutex_unlock(&state->req_mu);
}

static void sudoku_httpmask_interrupt_active(sudoku_httpmask_state_t *state) {
    pthread_mutex_lock(&state->req_mu);
    sudoku_http_conn_interrupt(state->active_pull);
    sudoku_http_conn_interrupt(state->active_push);
    pthread_mutex_unlock(&state->req_mu);
}

static int sudoku_httpmask_best_effort_post(sudoku_httpmask_state_t *state, const char *path) {
    sudoku_http_conn_t *conn = NULL;
    sudoku_http_body_reader_t body;
    uint8_t sink[256];
    size_t n = 0;
    if (!state || !path || !path[0]) return -1;
    if (sudoku_http_request_open(state, "POST", path, "/api/v1/upload", NULL, NULL, 0, &conn, &body) != 0) {
        return -1;
    }
    while (sudoku_http_body_read_some(&body, sink, sizeof(sink), &n) == 0 && n > 0) {
    }
    sudoku_http_conn_close(conn);
    free(conn);
    return body.status_code == 200 ? 0 : -1;
}

static int sudoku_httpmask_stream_post(sudoku_httpmask_state_t *state, const uint8_t *buf, size_t len) {
    sudoku_http_conn_t *conn = NULL;
    sudoku_http_body_reader_t body;
    uint8_t sink[256];
    size_t n = 0;
    if (sudoku_http_request_open(
            state,
            "POST",
            state->push_path,
            "/api/v1/upload",
            "Content-Type: application/octet-stream\r\n",
            buf,
            len,
            &conn,
            &body) != 0) {
        return -1;
    }
    sudoku_httpmask_set_active(state, 0, conn);
    while (sudoku_http_body_read_some(&body, sink, sizeof(sink), &n) == 0 && n > 0) {
    }
    sudoku_httpmask_set_active(state, 0, NULL);
    sudoku_http_conn_close(conn);
    free(conn);
    return body.status_code == 200 ? 0 : -1;
}

static int sudoku_httpmask_poll_encode(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_cap, size_t *dst_len) {
    size_t off = 0;
    while (src_len > 0) {
        size_t chunk = src_len;
        char line[32768];
        int n;
        if (chunk > 16384) chunk = 16384;
        n = sudoku_base64_encode(src, chunk, line, sizeof(line));
        if (n < 0 || off + (size_t)n + 1 > dst_cap) return -1;
        memcpy(dst + off, line, (size_t)n);
        off += (size_t)n;
        dst[off++] = '\n';
        src += chunk;
        src_len -= chunk;
    }
    *dst_len = off;
    return 0;
}

static int sudoku_httpmask_poll_post(sudoku_httpmask_state_t *state, const uint8_t *buf, size_t len) {
    sudoku_http_conn_t *conn = NULL;
    sudoku_http_body_reader_t body;
    uint8_t *encoded = NULL;
    uint8_t sink[256];
    size_t enc_len = 0;
    size_t n = 0;
    int result = -1;
    encoded = (uint8_t *)malloc(98304);
    if (!encoded) return -1;
    if (sudoku_httpmask_poll_encode(buf, len, encoded, 98304, &enc_len) != 0) goto done;
    if (sudoku_http_request_open(
            state,
            "POST",
            state->push_path,
            "/api/v1/upload",
            "Content-Type: text/plain\r\n",
            encoded,
            enc_len,
            &conn,
            &body) != 0) {
        goto done;
    }
    sudoku_httpmask_set_active(state, 0, conn);
    while (sudoku_http_body_read_some(&body, sink, sizeof(sink), &n) == 0 && n > 0) {
    }
    sudoku_httpmask_set_active(state, 0, NULL);
    sudoku_http_conn_close(conn);
    free(conn);
    result = body.status_code == 200 ? 0 : -1;
done:
    free(encoded);
    return result;
}

static void *sudoku_httpmask_push_main(void *opaque) {
    sudoku_httpmask_state_t *state = (sudoku_httpmask_state_t *)opaque;
    const size_t cap = state->mode == SUDOKU_TRANSPORT_HTTP_POLL ? 49152 : 262144;
    uint8_t *batch = (uint8_t *)malloc(cap);
    if (!batch) {
        sudoku_httpmask_mark_closed(state, 1);
        return NULL;
    }
    for (;;) {
        int closed = 0;
        size_t n = sudoku_httpmask_take_tx(state, batch, cap, 5, &closed);
        if (n > 0) {
            int rc = state->mode == SUDOKU_TRANSPORT_HTTP_POLL
                ? sudoku_httpmask_poll_post(state, batch, n)
                : sudoku_httpmask_stream_post(state, batch, n);
            if (rc != 0) {
                free(batch);
                sudoku_httpmask_mark_closed(state, 1);
                return NULL;
            }
        } else if (closed) {
            free(batch);
            return NULL;
        }
    }
}

static void *sudoku_httpmask_pull_main(void *opaque) {
    sudoku_httpmask_state_t *state = (sudoku_httpmask_state_t *)opaque;
    for (;;) {
        sudoku_http_conn_t *conn = NULL;
        sudoku_http_body_reader_t body;
        uint8_t buf[32768];
        size_t n = 0;
        int saw_any = 0;
        if (state->closed) return NULL;
        if (sudoku_http_request_open(state, "GET", state->pull_path, "/stream", NULL, NULL, 0, &conn, &body) != 0) {
            sudoku_httpmask_mark_closed(state, 1);
            return NULL;
        }
        sudoku_httpmask_set_active(state, 1, conn);
        if (body.status_code != 200) {
            sudoku_httpmask_set_active(state, 1, NULL);
            sudoku_http_conn_close(conn);
            free(conn);
            sudoku_httpmask_mark_closed(state, 1);
            return NULL;
        }
        if (state->mode == SUDOKU_TRANSPORT_HTTP_POLL) {
            char line[65536];
            size_t line_len = 0;
            while (sudoku_http_body_read_some(&body, buf, sizeof(buf), &n) == 0) {
                size_t off = 0;
                if (n == 0) break;
                saw_any = 1;
                while (off < n) {
                    uint8_t ch = buf[off++];
                    if (ch == '\r') continue;
                    if (ch == '\n') {
                        if (line_len > 0) {
                            uint8_t decoded[49152];
                            size_t dec_len = 0;
                            line[line_len] = '\0';
                            if (sudoku_base64_decode(line, decoded, sizeof(decoded), &dec_len) != 0 ||
                                sudoku_httpmask_queue_rx(state, decoded, dec_len) != 0) {
                                sudoku_httpmask_set_active(state, 1, NULL);
                                sudoku_http_conn_close(conn);
                                free(conn);
                                sudoku_httpmask_mark_closed(state, 1);
                                return NULL;
                            }
                            line_len = 0;
                        }
                        continue;
                    }
                    if (line_len + 1 >= sizeof(line)) {
                        sudoku_httpmask_set_active(state, 1, NULL);
                        sudoku_http_conn_close(conn);
                        free(conn);
                        sudoku_httpmask_mark_closed(state, 1);
                        return NULL;
                    }
                    line[line_len++] = (char)ch;
                }
            }
        } else {
            while (sudoku_http_body_read_some(&body, buf, sizeof(buf), &n) == 0) {
                if (n == 0) break;
                saw_any = 1;
                if (sudoku_httpmask_queue_rx(state, buf, n) != 0) {
                    sudoku_httpmask_set_active(state, 1, NULL);
                    sudoku_http_conn_close(conn);
                    free(conn);
                    sudoku_httpmask_mark_closed(state, 1);
                    return NULL;
                }
            }
        }
        sudoku_httpmask_set_active(state, 1, NULL);
        sudoku_http_conn_close(conn);
        free(conn);
        if (state->closed) return NULL;
        if (!saw_any) usleep(25000);
    }
}

static int sudoku_transport_enable_httpmask(
    sudoku_transport_t *tr,
    const sudoku_outbound_config_t *cfg,
    sudoku_transport_kind_t mode
) {
    sudoku_httpmask_state_t *state;
    if (!tr || !cfg) return -1;
    state = (sudoku_httpmask_state_t *)calloc(1, sizeof(*state));
    if (!state) return -1;
    memcpy(&state->cfg, cfg, sizeof(*cfg));
    state->mode = mode;
    pthread_mutex_init(&state->mu, NULL);
    pthread_mutex_init(&state->req_mu, NULL);
    pthread_cond_init(&state->rx_cond, NULL);
    pthread_cond_init(&state->tx_cond, NULL);
    sudoku_httpmask_host_header(cfg, state->header_host, sizeof(state->header_host));
    sudoku_apply_path_root(state->session_path, sizeof(state->session_path), cfg->httpmask_path_root, "/session");
    if (sudoku_httpmask_authorize(state) != 0) goto fail;
    if (pthread_create(&state->pull_thread, NULL, sudoku_httpmask_pull_main, state) != 0) goto fail;
    state->pull_started = 1;
    if (pthread_create(&state->push_thread, NULL, sudoku_httpmask_push_main, state) != 0) goto fail;
    state->push_started = 1;
    tr->kind = mode;
    tr->httpmask = state;
    tr->fd = -1;
    return 0;
fail:
    sudoku_httpmask_mark_closed(state, 1);
    sudoku_httpmask_interrupt_active(state);
    if (state->pull_started) pthread_join(state->pull_thread, NULL);
    if (state->push_started) pthread_join(state->push_thread, NULL);
    sudoku_byte_chunk_free_all(state->rx_head);
    sudoku_byte_chunk_free_all(state->tx_head);
    pthread_cond_destroy(&state->tx_cond);
    pthread_cond_destroy(&state->rx_cond);
    pthread_mutex_destroy(&state->req_mu);
    pthread_mutex_destroy(&state->mu);
    free(state);
    return -1;
}

static int sudoku_ws_handshake(sudoku_transport_t *tr, const sudoku_outbound_config_t *cfg) {
    uint8_t rand_key[16];
    char sec_key[64];
    char path[192];
    char auth_token[128];
    char auth_path[128];
    char host_header[320];
    char req[4096];
    char readbuf[4096];
    size_t total = 0;
    int req_len;
    const char *host_for_header = cfg->httpmask_host[0] ? cfg->httpmask_host : cfg->server_host;
    sudoku_apply_path_root(path, sizeof(path), cfg->httpmask_path_root, "/ws");
    sudoku_httpmask_auth_token(sudoku_seed_key_hex(cfg), "ws", "GET", "/ws", auth_token);
    snprintf(auth_path, sizeof(auth_path), "%s?auth=%s", path, auth_token);
#if SUDOKU_APPLE_SWIFT_BACKEND
    arc4random_buf(rand_key, sizeof(rand_key));
#else
    if (RAND_bytes(rand_key, sizeof(rand_key)) != 1) return -1;
#endif
    if (sudoku_base64_encode(rand_key, sizeof(rand_key), sec_key, sizeof(sec_key)) < 0) return -1;
    if ((cfg->httpmask_tls && cfg->server_port == 443) || (!cfg->httpmask_tls && cfg->server_port == 80)) {
        snprintf(host_header, sizeof(host_header), "%s", host_for_header);
    } else {
        snprintf(host_header, sizeof(host_header), "%s:%u", host_for_header, (unsigned)cfg->server_port);
    }
    req_len = snprintf(req, sizeof(req),
                       "GET %s HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "Upgrade: websocket\r\n"
                       "Connection: Upgrade\r\n"
                       "Sec-WebSocket-Key: %s\r\n"
                       "Sec-WebSocket-Version: 13\r\n"
                       "User-Agent: Mozilla/5.0\r\n"
                       "Accept: */*\r\n"
                       "Cache-Control: no-cache\r\n"
                       "Pragma: no-cache\r\n"
                       "X-Sudoku-Tunnel: ws\r\n"
                       "Authorization: Bearer %s\r\n"
                       "\r\n",
                       auth_path, host_header, sec_key, auth_token);
    if (req_len < 0 || (size_t)req_len >= sizeof(req)) return -1;
    if (sudoku_socket_send(tr, req, (size_t)req_len) < 0) return -1;
    while (total + 1 < sizeof(readbuf)) {
        ssize_t n = sudoku_socket_recv_some(tr, readbuf + total, sizeof(readbuf) - total - 1);
        if (n <= 0) return -1;
        total += (size_t)n;
        readbuf[total] = '\0';
        if (strstr(readbuf, "\r\n\r\n")) {
            if (strncmp(readbuf, "HTTP/1.1 101", 12) && strncmp(readbuf, "HTTP/1.0 101", 12)) {
                return -1;
            }
            tr->kind = SUDOKU_TRANSPORT_WS;
            return 0;
        }
    }
    return -1;
}

static int sudoku_write_masked_ws_frame_opcode(sudoku_transport_t *tr, uint8_t opcode, const uint8_t *payload, size_t len) {
    uint8_t header[14];
    uint8_t mask[4];
    uint8_t scratch[4096];
    size_t hdr_len = 0;
    size_t i;
    if (len && !payload) return -1;
    header[hdr_len++] = (uint8_t)(0x80 | (opcode & 0x0f));
    if (len <= 125) {
        header[hdr_len++] = (uint8_t)(0x80 | len);
    } else if (len <= 65535) {
        header[hdr_len++] = 0x80 | 126;
        header[hdr_len++] = (uint8_t)(len >> 8);
        header[hdr_len++] = (uint8_t)len;
    } else {
        header[hdr_len++] = 0x80 | 127;
        for (i = 0; i < 8; ++i) {
            header[hdr_len++] = (uint8_t)(len >> (56 - i * 8));
        }
    }
#if SUDOKU_APPLE_SWIFT_BACKEND
    arc4random_buf(mask, sizeof(mask));
#else
    if (RAND_bytes(mask, sizeof(mask)) != 1) return -1;
#endif
    memcpy(header + hdr_len, mask, 4);
    hdr_len += 4;
    if (sudoku_socket_send(tr, header, hdr_len) < 0) return -1;
    for (i = 0; i < len; ) {
        size_t chunk = len - i;
        size_t j;
        if (chunk > sizeof(scratch)) chunk = sizeof(scratch);
        for (j = 0; j < chunk; ++j) {
            scratch[j] = payload[i + j] ^ mask[(i + j) & 3];
        }
        if (sudoku_socket_send(tr, scratch, chunk) < 0) return -1;
        i += chunk;
    }
    return 0;
}

static int sudoku_write_masked_ws_frame(sudoku_transport_t *tr, const uint8_t *payload, size_t len) {
    return sudoku_write_masked_ws_frame_opcode(tr, 0x2, payload, len);
}

static int sudoku_read_ws_payload(sudoku_transport_t *tr, uint8_t *buf, size_t buf_cap, size_t *out_len) {
    uint8_t hdr[2];
    uint64_t payload_len;
    uint8_t ext[8];
    uint8_t opcode;
    if (sudoku_transport_read_exact_raw(tr, hdr, 2) != 0) return -1;
    opcode = hdr[0] & 0x0f;
    payload_len = hdr[1] & 0x7f;
    if (payload_len == 126) {
        if (sudoku_transport_read_exact_raw(tr, ext, 2) != 0) return -1;
        payload_len = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (payload_len == 127) {
        size_t i;
        if (sudoku_transport_read_exact_raw(tr, ext, 8) != 0) return -1;
        payload_len = 0;
        for (i = 0; i < 8; ++i) payload_len = (payload_len << 8) | ext[i];
    }
    if (hdr[1] & 0x80) {
        uint8_t mask[4];
        size_t i;
        if (sudoku_transport_read_exact_raw(tr, mask, 4) != 0) return -1;
        if (payload_len > buf_cap) return -1;
        if (sudoku_transport_read_exact_raw(tr, buf, (size_t)payload_len) != 0) return -1;
        for (i = 0; i < payload_len; ++i) buf[i] ^= mask[i & 3];
    } else {
        if (payload_len > buf_cap) return -1;
        if (sudoku_transport_read_exact_raw(tr, buf, (size_t)payload_len) != 0) return -1;
    }
    if (opcode == 0x9) {
        if (payload_len > 125) return -1;
        if (sudoku_write_masked_ws_frame_opcode(tr, 0xA, buf, (size_t)payload_len) != 0) return -1;
        return sudoku_read_ws_payload(tr, buf, buf_cap, out_len);
    }
    if (opcode == 0x8) return -1;
    if (opcode != 0x2 && opcode != 0x0) return -1;
    *out_len = (size_t)payload_len;
    return 0;
}

static int sudoku_transport_send_wire(sudoku_transport_t *tr, const uint8_t *buf, size_t len) {
    if (tr->kind == SUDOKU_TRANSPORT_WS) {
        return sudoku_write_masked_ws_frame(tr, buf, len);
    }
    if (tr->kind == SUDOKU_TRANSPORT_HTTP_STREAM || tr->kind == SUDOKU_TRANSPORT_HTTP_POLL) {
        return sudoku_httpmask_queue_tx(tr->httpmask, buf, len);
    }
    return sudoku_socket_send(tr, buf, len) < 0 ? -1 : 0;
}

static ssize_t sudoku_transport_recv_wire(sudoku_transport_t *tr, uint8_t *buf, size_t len) {
    if (tr->kind == SUDOKU_TRANSPORT_WS) {
        if (tr->rx_off == tr->rx_len) {
            tr->rx_off = 0;
            tr->rx_len = 0;
            if (sudoku_read_ws_payload(tr, tr->rx_buf, sizeof(tr->rx_buf), &tr->rx_len) != 0) {
                return -1;
            }
        }
        if (tr->rx_len == 0) return 0;
        if (len > tr->rx_len - tr->rx_off) len = tr->rx_len - tr->rx_off;
        memcpy(buf, tr->rx_buf + tr->rx_off, len);
        tr->rx_off += len;
        return (ssize_t)len;
    }
    if (tr->kind == SUDOKU_TRANSPORT_HTTP_STREAM || tr->kind == SUDOKU_TRANSPORT_HTTP_POLL) {
        return sudoku_httpmask_recv_wire(tr->httpmask, buf, len);
    }
    return sudoku_socket_recv_some(tr, buf, len);
}

static int sudoku_transport_send(sudoku_transport_t *tr, const uint8_t *buf, size_t len) {
    if (!tr->obfs_enabled) {
        return sudoku_transport_send_wire(tr, buf, len);
    }

    while (len > 0) {
        uint8_t encoded[8192 * 6 + 8];
        size_t chunk = len;
        size_t enc_len;
        if (chunk > 8192) chunk = 8192;
        enc_len = sudoku_encode_pure(
            encoded,
            sizeof(encoded),
            tr->uplink_table,
            &tr->rng,
            tr->padding_threshold,
            buf,
            chunk
        );
        if (enc_len == 0 && chunk != 0) return -1;
        if (sudoku_transport_send_wire(tr, encoded, enc_len) != 0) return -1;
        buf += chunk;
        len -= chunk;
    }
    return 0;
}

static ssize_t sudoku_transport_recv(sudoku_transport_t *tr, uint8_t *buf, size_t len) {
    if (!tr->obfs_enabled) {
        return sudoku_transport_recv_wire(tr, buf, len);
    }

    if (tr->plain_off < tr->plain_len) {
        size_t n = tr->plain_len - tr->plain_off;
        if (n > len) n = len;
        memcpy(buf, tr->plain_buf + tr->plain_off, n);
        tr->plain_off += n;
        if (tr->plain_off == tr->plain_len) {
            tr->plain_off = 0;
            tr->plain_len = 0;
        }
        return (ssize_t)n;
    }

    while (1) {
        uint8_t wire_buf[8192];
        size_t out_len = 0;
        int err = 0;
        ssize_t n = sudoku_transport_recv_wire(tr, wire_buf, sizeof(wire_buf));
        if (n <= 0) return n;
        if (tr->pure_downlink) {
            out_len = sudoku_decode_pure(
                &tr->pure_decoder,
                tr->downlink_table,
                wire_buf,
                (size_t)n,
                tr->plain_buf,
                sizeof(tr->plain_buf),
                &err
            );
        } else {
            out_len = sudoku_decode_packed(
                &tr->packed_decoder,
                tr->downlink_table,
                wire_buf,
                (size_t)n,
                tr->plain_buf,
                sizeof(tr->plain_buf),
                &err
            );
        }
        if (err != 0) return -1;
        if (out_len == 0) continue;
        tr->plain_len = out_len;
        tr->plain_off = 0;
        if (out_len > len) {
            memcpy(buf, tr->plain_buf, len);
            tr->plain_off = len;
            return (ssize_t)len;
        }
        memcpy(buf, tr->plain_buf, out_len);
        tr->plain_len = 0;
        tr->plain_off = 0;
        return (ssize_t)out_len;
    }
}

static int sudoku_transport_read_exact(sudoku_transport_t *tr, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = sudoku_transport_recv(tr, p + got, len - got);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

static int sudoku_write_legacy_httpmask(sudoku_transport_t *tr, const sudoku_outbound_config_t *cfg) {
    char path[192];
    char req[1024];
    const char *host = cfg->httpmask_host[0] ? cfg->httpmask_host : cfg->server_host;
    int req_len;
    sudoku_apply_path_root(path, sizeof(path), cfg->httpmask_path_root, "/api");
    req_len = snprintf(req, sizeof(req),
                       "POST %s HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "User-Agent: Mozilla/5.0\r\n"
                       "Accept: */*\r\n"
                       "Connection: keep-alive\r\n"
                       "Content-Type: application/octet-stream\r\n"
                       "Content-Length: 1048576\r\n"
                       "\r\n",
                       path, host);
    if (req_len < 0 || (size_t)req_len >= sizeof(req)) return -1;
    return sudoku_transport_send_wire(tr, (const uint8_t *)req, (size_t)req_len);
}

static int sudoku_hkdf_expand(
    const uint8_t *prk, size_t prk_len,
    const char *info,
    uint8_t *out, size_t out_len
) {
    uint8_t t[SUDOKU_DIGEST_MAX_SIZE];
    size_t t_len = 0;
    size_t info_len = strlen(info);
    size_t produced = 0;
    uint8_t counter = 1;
    sudoku_bytespan_t parts[3];

    while (produced < out_len) {
        size_t chunk;
        size_t part_count = 0;

        if (t_len > 0) {
            parts[part_count].data = t;
            parts[part_count].len = t_len;
            part_count++;
        }
        if (info_len > 0) {
            parts[part_count].data = (const uint8_t *)info;
            parts[part_count].len = info_len;
            part_count++;
        }
        parts[part_count].data = &counter;
        parts[part_count].len = 1;
        part_count++;

        if (sudoku_hmac_sha256_parts(prk, prk_len, parts, part_count, t) != 0) return -1;
        t_len = 32;
        chunk = out_len - produced;
        if (chunk > t_len) chunk = t_len;
        memcpy(out + produced, t, chunk);
        produced += chunk;
        counter++;
    }
    return 0;
}

static int sudoku_hkdf_extract(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    uint8_t out[32]
) {
#if SUDOKU_APPLE_SWIFT_BACKEND
    CCHmac(kCCHmacAlgSHA256, salt, salt_len, ikm, ikm_len, out);
    return 0;
#else
    unsigned int len = 0;
    HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, out, &len);
    return len == 32 ? 0 : -1;
#endif
}

static int sudoku_derive_psk_bases(const char *psk, uint8_t c2s[32], uint8_t s2c[32]) {
    uint8_t sum[32];
    sudoku_sha256_string(psk, sum);
    if (sudoku_hkdf_expand(sum, 32, "sudoku-psk-c2s", c2s, 32) != 0) return -1;
    if (sudoku_hkdf_expand(sum, 32, "sudoku-psk-s2c", s2c, 32) != 0) return -1;
    return 0;
}

static int sudoku_derive_session_bases(
    const char *psk,
    const uint8_t *shared, size_t shared_len,
    const uint8_t nonce[16],
    uint8_t c2s[32], uint8_t s2c[32]
) {
    uint8_t salt[32];
    uint8_t prk[32];
    uint8_t ikm[64];
    sudoku_sha256_string(psk, salt);
    memcpy(ikm, shared, shared_len);
    memcpy(ikm + shared_len, nonce, 16);
    if (sudoku_hkdf_extract(salt, 32, ikm, shared_len + 16, prk) != 0) return -1;
    if (sudoku_hkdf_expand(prk, 32, "sudoku-session-c2s", c2s, 32) != 0) return -1;
    if (sudoku_hkdf_expand(prk, 32, "sudoku-session-s2c", s2c, 32) != 0) return -1;
    return 0;
}

static int sudoku_record_epoch_key(
    const uint8_t base[32],
    sudoku_aead_kind_t method,
    uint32_t epoch,
    uint8_t out[32]
) {
    uint8_t epoch_be[4];
    const char *method_name = method == SUDOKU_AEAD_AES128GCM ? "aes-128-gcm" : "chacha20-poly1305";
    sudoku_bytespan_t parts[3];
    epoch_be[0] = (uint8_t)(epoch >> 24);
    epoch_be[1] = (uint8_t)(epoch >> 16);
    epoch_be[2] = (uint8_t)(epoch >> 8);
    epoch_be[3] = (uint8_t)epoch;
    parts[0].data = (const uint8_t *)"sudoku-record:";
    parts[0].len = 14;
    parts[1].data = (const uint8_t *)method_name;
    parts[1].len = strlen(method_name);
    parts[2].data = epoch_be;
    parts[2].len = sizeof(epoch_be);
    return sudoku_hmac_sha256_parts(base, 32, parts, 3, out);
}

#if !SUDOKU_APPLE_SWIFT_BACKEND
static int sudoku_record_cipher_init(EVP_CIPHER_CTX **ctxp, sudoku_aead_kind_t method, const uint8_t key[32], int enc) {
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (method == SUDOKU_AEAD_AES128GCM) cipher = EVP_aes_128_gcm();
    else cipher = EVP_chacha20_poly1305();
    if (!ctx) return -1;
    if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) goto fail;
    if (EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, enc) != 1) goto fail;
    *ctxp = ctx;
    return 0;
fail:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}
#endif

static int sudoku_record_ensure_send_ctx(sudoku_record_conn_t *rc) {
#if SUDOKU_APPLE_SWIFT_BACKEND
    if (rc->method == SUDOKU_AEAD_NONE) return 0;
    rc->send_ctx_epoch = rc->send_epoch;
    return 0;
#else
    uint8_t key[32];
    if (rc->method == SUDOKU_AEAD_NONE) return 0;
    if (rc->send_ctx && rc->send_ctx_epoch == rc->send_epoch) return 0;
    if (rc->send_ctx) EVP_CIPHER_CTX_free(rc->send_ctx);
    rc->send_ctx = NULL;
    if (sudoku_record_epoch_key(rc->keys.base_send, rc->method, rc->send_epoch, key) != 0) return -1;
    if (sudoku_record_cipher_init(&rc->send_ctx, rc->method, key, 1) != 0) return -1;
    rc->send_ctx_epoch = rc->send_epoch;
    return 0;
#endif
}

static int sudoku_record_ensure_recv_ctx(sudoku_record_conn_t *rc, uint32_t epoch) {
#if SUDOKU_APPLE_SWIFT_BACKEND
    if (rc->method == SUDOKU_AEAD_NONE) return 0;
    rc->recv_ctx_epoch = epoch;
    return 0;
#else
    uint8_t key[32];
    if (rc->method == SUDOKU_AEAD_NONE) return 0;
    if (rc->recv_ctx && rc->recv_ctx_epoch == epoch) return 0;
    if (rc->recv_ctx) EVP_CIPHER_CTX_free(rc->recv_ctx);
    rc->recv_ctx = NULL;
    if (sudoku_record_epoch_key(rc->keys.base_recv, rc->method, epoch, key) != 0) return -1;
    if (sudoku_record_cipher_init(&rc->recv_ctx, rc->method, key, 0) != 0) return -1;
    rc->recv_ctx_epoch = epoch;
    return 0;
#endif
}

static sudoku_record_conn_t *sudoku_record_conn_new(
    sudoku_transport_t *tr,
    sudoku_aead_kind_t method,
    const uint8_t base_send[32],
    const uint8_t base_recv[32]
) {
    sudoku_record_conn_t *rc = (sudoku_record_conn_t *)calloc(1, sizeof(*rc));
    if (!rc) return NULL;
    rc->transport = tr;
    rc->method = method;
    memcpy(rc->keys.base_send, base_send, 32);
    memcpy(rc->keys.base_recv, base_recv, 32);
    pthread_mutex_init(&rc->write_mu, NULL);
    pthread_mutex_init(&rc->read_mu, NULL);
    if (sudoku_random_nonzero_u32(&rc->send_epoch) != 0 || sudoku_random_nonzero_u64(&rc->send_seq) != 0) {
        pthread_mutex_destroy(&rc->write_mu);
        pthread_mutex_destroy(&rc->read_mu);
        free(rc);
        return NULL;
    }
    return rc;
}

static void sudoku_record_conn_free(sudoku_record_conn_t *rc) {
    if (!rc) return;
#if !SUDOKU_APPLE_SWIFT_BACKEND
    if (rc->send_ctx) EVP_CIPHER_CTX_free(rc->send_ctx);
    if (rc->recv_ctx) EVP_CIPHER_CTX_free(rc->recv_ctx);
#endif
    pthread_mutex_destroy(&rc->write_mu);
    pthread_mutex_destroy(&rc->read_mu);
    free(rc);
}

static int sudoku_record_rekey(sudoku_record_conn_t *rc, const uint8_t base_send[32], const uint8_t base_recv[32]) {
    memcpy(rc->keys.base_send, base_send, 32);
    memcpy(rc->keys.base_recv, base_recv, 32);
    if (sudoku_random_nonzero_u32(&rc->send_epoch) != 0 || sudoku_random_nonzero_u64(&rc->send_seq) != 0) return -1;
    rc->send_bytes = 0;
    rc->send_epoch_updates = 0;
    rc->recv_epoch = 0;
    rc->recv_seq = 0;
    rc->recv_initialized = 0;
    rc->read_len = rc->read_off = 0;
#if !SUDOKU_APPLE_SWIFT_BACKEND
    if (rc->send_ctx) { EVP_CIPHER_CTX_free(rc->send_ctx); rc->send_ctx = NULL; }
    if (rc->recv_ctx) { EVP_CIPHER_CTX_free(rc->recv_ctx); rc->recv_ctx = NULL; }
#endif
    return 0;
}

static int sudoku_record_maybe_bump_epoch(sudoku_record_conn_t *rc, size_t added_plain) {
    if (rc->method == SUDOKU_AEAD_NONE) return 0;
    rc->send_bytes += (int64_t)added_plain;
    if (rc->send_bytes < (int64_t)(SUDOKU_KEY_UPDATE_AFTER_BYTES * (rc->send_epoch_updates + 1))) {
        return 0;
    }
    rc->send_epoch++;
    rc->send_epoch_updates++;
    if (sudoku_random_nonzero_u64(&rc->send_seq) != 0) return -1;
    return 0;
}

static ssize_t sudoku_record_send(sudoku_record_conn_t *rc, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t total = 0;
    pthread_mutex_lock(&rc->write_mu);
    if (rc->method == SUDOKU_AEAD_NONE) {
        int r = sudoku_transport_send(rc->transport, p, len);
        pthread_mutex_unlock(&rc->write_mu);
        return r == 0 ? (ssize_t)len : -1;
    }
    while (total < len) {
        uint8_t header[12];
        uint8_t frame[2 + 12 + 65535];
#if !SUDOKU_APPLE_SWIFT_BACKEND
        int outl = 0, finl = 0;
#endif
        size_t chunk = len - total;
        size_t max_plain = 65535 - 12 - 16;
        int cipher_len;
        if (chunk > max_plain) chunk = max_plain;
        if (sudoku_record_ensure_send_ctx(rc) != 0) goto fail;
        header[0] = (uint8_t)(rc->send_epoch >> 24);
        header[1] = (uint8_t)(rc->send_epoch >> 16);
        header[2] = (uint8_t)(rc->send_epoch >> 8);
        header[3] = (uint8_t)rc->send_epoch;
        header[4] = (uint8_t)(rc->send_seq >> 56);
        header[5] = (uint8_t)(rc->send_seq >> 48);
        header[6] = (uint8_t)(rc->send_seq >> 40);
        header[7] = (uint8_t)(rc->send_seq >> 32);
        header[8] = (uint8_t)(rc->send_seq >> 24);
        header[9] = (uint8_t)(rc->send_seq >> 16);
        header[10] = (uint8_t)(rc->send_seq >> 8);
        header[11] = (uint8_t)rc->send_seq;
        rc->send_seq++;
        memcpy(frame + 2, header, 12);
#if SUDOKU_APPLE_SWIFT_BACKEND
        {
            uint8_t key[32];
            int32_t kind = rc->method == SUDOKU_AEAD_AES128GCM
                ? SUDOKU_SWIFT_AEAD_AES128_GCM_LOCAL
                : SUDOKU_SWIFT_AEAD_CHACHA20_POLY1305_LOCAL;
            size_t key_len = rc->method == SUDOKU_AEAD_AES128GCM ? 16 : 32;
            if (sudoku_record_epoch_key(rc->keys.base_send, rc->method, rc->send_epoch, key) != 0) goto fail;
            if (sudoku_swift_crypto_aead_encrypt(
                    frame + 14,
                    key,
                    key_len,
                    header,
                    12,
                    p + total,
                    chunk,
                    header,
                    12,
                    kind
                ) != 0) {
                goto fail;
            }
            cipher_len = (int)(chunk + 16);
        }
#else
        EVP_CIPHER_CTX_ctrl(rc->send_ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
        EVP_CipherInit_ex(rc->send_ctx, NULL, NULL, NULL, header, 1);
        EVP_CipherUpdate(rc->send_ctx, NULL, &outl, header, 12);
        EVP_CipherUpdate(rc->send_ctx, frame + 14, &outl, p + total, (int)chunk);
        cipher_len = outl;
        EVP_CipherFinal_ex(rc->send_ctx, frame + 14 + cipher_len, &finl);
        cipher_len += finl;
        EVP_CIPHER_CTX_ctrl(rc->send_ctx, EVP_CTRL_AEAD_GET_TAG, 16, frame + 14 + cipher_len);
        cipher_len += 16;
#endif
        frame[0] = (uint8_t)((12 + cipher_len) >> 8);
        frame[1] = (uint8_t)(12 + cipher_len);
        if (sudoku_transport_send(rc->transport, frame, 2 + 12 + cipher_len) != 0) goto fail;
        total += chunk;
        if (sudoku_record_maybe_bump_epoch(rc, chunk) != 0) goto fail;
    }
    pthread_mutex_unlock(&rc->write_mu);
    return (ssize_t)total;
fail:
    pthread_mutex_unlock(&rc->write_mu);
    return -1;
}

static ssize_t sudoku_record_recv(sudoku_record_conn_t *rc, void *buf, size_t len) {
    uint8_t *out = (uint8_t *)buf;
    pthread_mutex_lock(&rc->read_mu);
    if (rc->read_off < rc->read_len) {
        size_t n = rc->read_len - rc->read_off;
        if (n > len) n = len;
        memcpy(out, rc->read_buf + rc->read_off, n);
        rc->read_off += n;
        if (rc->read_off == rc->read_len) rc->read_off = rc->read_len = 0;
        pthread_mutex_unlock(&rc->read_mu);
        return (ssize_t)n;
    }
    if (rc->method == SUDOKU_AEAD_NONE) {
        ssize_t n = sudoku_transport_recv(rc->transport, out, len);
        pthread_mutex_unlock(&rc->read_mu);
        return n;
    }
    while (1) {
        uint8_t lenbuf[2];
        uint8_t body[65535];
        uint8_t *header;
        uint8_t *ciphertext;
        int body_len;
#if !SUDOKU_APPLE_SWIFT_BACKEND
        int plain_len = 0, finl = 0;
#endif
        uint32_t epoch;
        uint64_t seq;
        if (sudoku_transport_read_exact(rc->transport, lenbuf, 2) != 0) goto fail;
        body_len = ((int)lenbuf[0] << 8) | lenbuf[1];
        if (body_len < 12 || body_len > 65535) goto fail;
        if (sudoku_transport_read_exact(rc->transport, body, (size_t)body_len) != 0) goto fail;
        header = body;
        ciphertext = body + 12;
        epoch = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) | ((uint32_t)header[2] << 8) | (uint32_t)header[3];
        seq = ((uint64_t)header[4] << 56) | ((uint64_t)header[5] << 48) | ((uint64_t)header[6] << 40) | ((uint64_t)header[7] << 32) |
              ((uint64_t)header[8] << 24) | ((uint64_t)header[9] << 16) | ((uint64_t)header[10] << 8) | (uint64_t)header[11];
        if (rc->recv_initialized) {
            if (epoch < rc->recv_epoch) goto fail;
            if (epoch == rc->recv_epoch && seq != rc->recv_seq) goto fail;
            if (epoch > rc->recv_epoch && epoch - rc->recv_epoch > 8) goto fail;
        }
        if (sudoku_record_ensure_recv_ctx(rc, epoch) != 0) goto fail;
#if SUDOKU_APPLE_SWIFT_BACKEND
        {
            uint8_t key[32];
            int32_t kind = rc->method == SUDOKU_AEAD_AES128GCM
                ? SUDOKU_SWIFT_AEAD_AES128_GCM_LOCAL
                : SUDOKU_SWIFT_AEAD_CHACHA20_POLY1305_LOCAL;
            size_t key_len = rc->method == SUDOKU_AEAD_AES128GCM ? 16 : 32;
            if (body_len < 12 + 16) goto fail;
            if (sudoku_record_epoch_key(rc->keys.base_recv, rc->method, epoch, key) != 0) goto fail;
            if (sudoku_swift_crypto_aead_decrypt(
                    rc->read_buf,
                    key,
                    key_len,
                    header,
                    12,
                    ciphertext,
                    (size_t)(body_len - 12),
                    header,
                    12,
                    kind
                ) != 0) {
                goto fail;
            }
            rc->read_len = (size_t)(body_len - 12 - 16);
        }
#else
        EVP_CIPHER_CTX_ctrl(rc->recv_ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
        EVP_CipherInit_ex(rc->recv_ctx, NULL, NULL, NULL, header, 0);
        EVP_CipherUpdate(rc->recv_ctx, NULL, &plain_len, header, 12);
        EVP_CipherUpdate(rc->recv_ctx, rc->read_buf, &plain_len, ciphertext, body_len - 12 - 16);
        EVP_CIPHER_CTX_ctrl(rc->recv_ctx, EVP_CTRL_AEAD_SET_TAG, 16, ciphertext + (body_len - 12 - 16));
        if (EVP_CipherFinal_ex(rc->recv_ctx, rc->read_buf + plain_len, &finl) != 1) goto fail;
        rc->read_len = (size_t)(plain_len + finl);
#endif
        rc->read_off = 0;
        rc->recv_epoch = epoch;
        rc->recv_seq = seq + 1;
        rc->recv_initialized = 1;
        if (rc->read_len == 0) continue;
        if (rc->read_len > len) {
            memcpy(out, rc->read_buf, len);
            rc->read_off = len;
            pthread_mutex_unlock(&rc->read_mu);
            return (ssize_t)len;
        } else {
            size_t copied = rc->read_len;
            memcpy(out, rc->read_buf, copied);
            rc->read_off = rc->read_len = 0;
            pthread_mutex_unlock(&rc->read_mu);
            return (ssize_t)copied;
        }
    }
fail:
    pthread_mutex_unlock(&rc->read_mu);
    return -1;
}

static int sudoku_write_all_record(sudoku_record_conn_t *rc, const uint8_t *buf, size_t len) {
    return sudoku_record_send(rc, buf, len) == (ssize_t)len ? 0 : -1;
}

static int sudoku_read_exact_record(sudoku_record_conn_t *rc, void *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = sudoku_record_recv(rc, (uint8_t *)buf + got, len - got);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

static int sudoku_write_kip_message(sudoku_record_conn_t *rc, uint8_t type, const uint8_t *payload, size_t payload_len) {
    uint8_t hdr[6];
    hdr[0] = 'k'; hdr[1] = 'i'; hdr[2] = 'p'; hdr[3] = type;
    hdr[4] = (uint8_t)(payload_len >> 8);
    hdr[5] = (uint8_t)payload_len;
    if (sudoku_write_all_record(rc, hdr, 6) != 0) return -1;
    if (payload_len && sudoku_write_all_record(rc, payload, payload_len) != 0) return -1;
    return 0;
}

static int sudoku_read_kip_message(sudoku_record_conn_t *rc, uint8_t *type, uint8_t *payload, size_t *payload_len) {
    uint8_t hdr[6];
    size_t len;
    if (sudoku_read_exact_record(rc, hdr, 6) != 0) return -1;
    if (hdr[0] != 'k' || hdr[1] != 'i' || hdr[2] != 'p') return -1;
    len = ((size_t)hdr[4] << 8) | hdr[5];
    if (payload && len && sudoku_read_exact_record(rc, payload, len) != 0) return -1;
    *type = hdr[3];
    *payload_len = len;
    return 0;
}

static void sudoku_user_hash(const sudoku_outbound_config_t *cfg, uint8_t out[8]) {
    uint8_t sum[32];
    uint8_t public_key[32];
    size_t public_key_len = 0;
    if (cfg->private_key_len) {
        sudoku_sha256_bytes(cfg->private_key, cfg->private_key_len, sum);
    } else {
        if (sudoku_hex_decode(cfg->key_hex, public_key, sizeof(public_key), &public_key_len) != 0 || public_key_len != 32) {
            sudoku_sha256_string(cfg->key_hex, sum);
        } else {
            sudoku_sha256_bytes(public_key, public_key_len, sum);
        }
    }
    memcpy(out, sum, 8);
}

static int sudoku_x25519_generate(uint8_t priv[32], uint8_t pub[32]) {
#if SUDOKU_APPLE_SWIFT_BACKEND
    return sudoku_swift_crypto_x25519_generate(priv, pub);
#else
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pkey = NULL;
    size_t priv_len = 32, pub_len = 32;
    if (!ctx) return -1;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto fail;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto fail;
    if (EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len) <= 0) goto fail;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) <= 0) goto fail;
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 0;
fail:
    if (pkey) EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return -1;
#endif
}

static int sudoku_x25519_shared(const uint8_t priv[32], const uint8_t peer_pub[32], uint8_t out[32]) {
#if SUDOKU_APPLE_SWIFT_BACKEND
    return sudoku_swift_crypto_x25519_shared(priv, peer_pub, out);
#else
    EVP_PKEY *privkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    EVP_PKEY *peerkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    size_t out_len = 32;
    if (!privkey || !peerkey || !ctx) goto fail;
    if (EVP_PKEY_derive_init(ctx) <= 0) goto fail;
    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) goto fail;
    if (EVP_PKEY_derive(ctx, out, &out_len) <= 0 || out_len != 32) goto fail;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privkey);
    EVP_PKEY_free(peerkey);
    return 0;
fail:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (privkey) EVP_PKEY_free(privkey);
    if (peerkey) EVP_PKEY_free(peerkey);
    return -1;
#endif
}

static int sudoku_kip_handshake_client(sudoku_record_conn_t *rc, const sudoku_outbound_config_t *cfg, const sudoku_table_t *table) {
    uint8_t client_priv[32], client_pub[32], nonce[16], user_hash[8];
    uint8_t payload[8 + 8 + 16 + 32 + 4 + 4];
    uint8_t resp[64];
    size_t resp_len = 0;
    uint8_t typ;
    uint8_t shared[32], sess_c2s[32], sess_s2c[32];
    uint64_t ts = (uint64_t)time(NULL);
    uint32_t feats = 0x1f;

    if (sudoku_x25519_generate(client_priv, client_pub) != 0) return -1;
#if SUDOKU_APPLE_SWIFT_BACKEND
    arc4random_buf(nonce, sizeof(nonce));
#else
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return -1;
#endif
    sudoku_user_hash(cfg, user_hash);

    payload[0] = (uint8_t)(ts >> 56);
    payload[1] = (uint8_t)(ts >> 48);
    payload[2] = (uint8_t)(ts >> 40);
    payload[3] = (uint8_t)(ts >> 32);
    payload[4] = (uint8_t)(ts >> 24);
    payload[5] = (uint8_t)(ts >> 16);
    payload[6] = (uint8_t)(ts >> 8);
    payload[7] = (uint8_t)ts;
    memcpy(payload + 8, user_hash, 8);
    memcpy(payload + 16, nonce, 16);
    memcpy(payload + 32, client_pub, 32);
    payload[64] = (uint8_t)(feats >> 24);
    payload[65] = (uint8_t)(feats >> 16);
    payload[66] = (uint8_t)(feats >> 8);
    payload[67] = (uint8_t)feats;
    payload[68] = (uint8_t)(table->hint >> 24);
    payload[69] = (uint8_t)(table->hint >> 16);
    payload[70] = (uint8_t)(table->hint >> 8);
    payload[71] = (uint8_t)table->hint;

    if (sudoku_write_kip_message(rc, 0x01, payload, 72) != 0) return -1;
    if (sudoku_read_kip_message(rc, &typ, resp, &resp_len) != 0) return -1;
    if (typ != 0x02 || resp_len != 52) return -1;
    if (memcmp(resp, nonce, 16) != 0) return -1;
    if (sudoku_x25519_shared(client_priv, resp + 16, shared) != 0) return -1;
    if (sudoku_derive_session_bases(sudoku_seed_key_hex(cfg), shared, 32, nonce, sess_c2s, sess_s2c) != 0) return -1;
    if (sudoku_record_rekey(rc, sess_c2s, sess_s2c) != 0) return -1;
    return 0;
}

static int sudoku_write_address(uint8_t *buf, size_t buf_cap, const char *host, uint16_t port, size_t *out_len) {
    uint8_t ipbuf[16];
    size_t off = 0;
    if (inet_pton(AF_INET, host, ipbuf) == 1) {
        if (buf_cap < 1 + 4 + 2) return -1;
        buf[off++] = 0x01;
        memcpy(buf + off, ipbuf, 4);
        off += 4;
    } else if (inet_pton(AF_INET6, host, ipbuf) == 1) {
        if (buf_cap < 1 + 16 + 2) return -1;
        buf[off++] = 0x04;
        memcpy(buf + off, ipbuf, 16);
        off += 16;
    } else {
        size_t host_len = strlen(host);
        if (host_len > 255 || buf_cap < 1 + 1 + host_len + 2) return -1;
        buf[off++] = 0x03;
        buf[off++] = (uint8_t)host_len;
        memcpy(buf + off, host, host_len);
        off += host_len;
    }
    buf[off++] = (uint8_t)(port >> 8);
    buf[off++] = (uint8_t)port;
    *out_len = off;
    return 0;
}

static int sudoku_open_tcp(sudoku_record_conn_t *rc, const char *host, uint16_t port) {
    uint8_t addr[300];
    size_t addr_len = 0;
    if (sudoku_write_address(addr, sizeof(addr), host, port, &addr_len) != 0) return -1;
    return sudoku_write_kip_message(rc, 0x10, addr, addr_len);
}

static int sudoku_start_uot(sudoku_record_conn_t *rc) {
    return sudoku_write_kip_message(rc, 0x12, NULL, 0);
}

static int sudoku_start_mux(sudoku_record_conn_t *rc) {
    return sudoku_write_kip_message(rc, 0x11, NULL, 0);
}

static int sudoku_read_address(
    const uint8_t *buf,
    size_t len,
    char *host,
    size_t host_cap,
    uint16_t *port,
    size_t *consumed
) {
    size_t off = 0;
    uint8_t atyp;
    if (!buf || len < 1 || !host || host_cap == 0 || !port) return -1;
    atyp = buf[off++];
    if (atyp == 0x01) {
        if (len < off + 4 + 2) return -1;
        if (!inet_ntop(AF_INET, buf + off, host, (socklen_t)host_cap)) return -1;
        off += 4;
    } else if (atyp == 0x04) {
        if (len < off + 16 + 2) return -1;
        if (!inet_ntop(AF_INET6, buf + off, host, (socklen_t)host_cap)) return -1;
        off += 16;
    } else if (atyp == 0x03) {
        uint8_t host_len;
        if (len < off + 1) return -1;
        host_len = buf[off++];
        if (len < off + host_len + 2 || host_len + 1 > host_cap) return -1;
        memcpy(host, buf + off, host_len);
        host[host_len] = '\0';
        off += host_len;
    } else {
        return -1;
    }
    *port = (uint16_t)(((uint16_t)buf[off] << 8) | buf[off + 1]);
    off += 2;
    if (consumed) *consumed = off;
    return 0;
}

static int sudoku_connect_base(const sudoku_outbound_config_t *cfg, sudoku_transport_t **out_transport, sudoku_record_conn_t **out_record, sudoku_table_pair_t *out_tables) {
    int fd = -1;
    sudoku_transport_t *tr = NULL;
    sudoku_record_conn_t *rc = NULL;
    uint8_t psk_c2s[32], psk_s2c[32];
    char server_name[256];

    if (sudoku_pick_client_tables(cfg, out_tables) != 0) return -1;
    if (!cfg->httpmask_disable &&
        (!strcmp(cfg->httpmask_mode, "stream") || !strcmp(cfg->httpmask_mode, "poll") || !strcmp(cfg->httpmask_mode, "auto"))) {
        tr = sudoku_transport_new(-1);
        if (!tr) goto fail;
        if (!strcmp(cfg->httpmask_mode, "poll")) {
            if (sudoku_transport_enable_httpmask(tr, cfg, SUDOKU_TRANSPORT_HTTP_POLL) != 0) goto fail;
        } else if (!strcmp(cfg->httpmask_mode, "stream")) {
            if (sudoku_transport_enable_httpmask(tr, cfg, SUDOKU_TRANSPORT_HTTP_STREAM) != 0) goto fail;
        } else {
            if (sudoku_transport_enable_httpmask(tr, cfg, SUDOKU_TRANSPORT_HTTP_STREAM) != 0) {
                sudoku_transport_close(tr);
                tr = sudoku_transport_new(-1);
                if (!tr) goto fail;
                if (sudoku_transport_enable_httpmask(tr, cfg, SUDOKU_TRANSPORT_HTTP_POLL) != 0) goto fail;
            }
        }
    } else {
        int use_tls = (!cfg->httpmask_disable && !strcmp(cfg->httpmask_mode, "ws") && cfg->httpmask_tls) ? 1 : 0;
        snprintf(server_name, sizeof(server_name), "%s", cfg->httpmask_host[0] ? cfg->httpmask_host : cfg->server_host);
        fd = sudoku_tcp_connect_ex(cfg, cfg->server_host, cfg->server_port, use_tls, server_name);
        if (fd < 0) goto fail;
        tr = sudoku_transport_new(fd);
        if (!tr) goto fail;
        if (!cfg->httpmask_disable && !strcmp(cfg->httpmask_mode, "ws")) {
            if (cfg->httpmask_tls) {
                if (sudoku_transport_enable_tls(tr, server_name) != 0) goto fail;
            }
            if (sudoku_ws_handshake(tr, cfg) != 0) goto fail;
        } else if (!cfg->httpmask_disable && !strcmp(cfg->httpmask_mode, "legacy")) {
            if (sudoku_write_legacy_httpmask(tr, cfg) != 0) goto fail;
        }
    }

    if (sudoku_derive_psk_bases(sudoku_seed_key_hex(cfg), psk_c2s, psk_s2c) != 0) goto fail;
    if (sudoku_transport_enable_obfs(tr, out_tables, cfg->padding_min, cfg->padding_max, cfg->enable_pure_downlink) != 0) goto fail;
    rc = sudoku_record_conn_new(tr, sudoku_parse_aead(cfg->aead_method), psk_c2s, psk_s2c);
    if (!rc) goto fail;
    if (sudoku_kip_handshake_client(rc, cfg, &out_tables->uplink) != 0) goto fail;

    *out_transport = tr;
    *out_record = rc;
    return 0;
fail:
    if (rc) sudoku_record_conn_free(rc);
    if (tr) sudoku_transport_close(tr);
    sudoku_table_pair_free(out_tables);
    return -1;
}

int sudoku_client_connect_tcp(
    const sudoku_outbound_config_t *cfg,
    const char *target_host,
    uint16_t target_port,
    sudoku_client_conn_t **out_conn
) {
    sudoku_client_conn_t *conn;
    if (!cfg || !target_host || !target_port || !out_conn) return -1;
    conn = (sudoku_client_conn_t *)calloc(1, sizeof(*conn));
    if (!conn) return -1;
    if (sudoku_connect_base(cfg, &conn->transport, &conn->record, &conn->tables) != 0) {
        free(conn);
        return -1;
    }
    if (sudoku_open_tcp(conn->record, target_host, target_port) != 0) {
        sudoku_client_close(conn);
        return -1;
    }
    *out_conn = conn;
    return 0;
}

ssize_t sudoku_client_send(sudoku_client_conn_t *conn, const void *buf, size_t len) {
    if (!conn || !conn->record || (!buf && len)) return -1;
    if (len == 0) return 0;
    return sudoku_record_send(conn->record, buf, len);
}

ssize_t sudoku_client_recv(sudoku_client_conn_t *conn, void *buf, size_t len) {
    if (!conn || !conn->record || (!buf && len)) return -1;
    if (len == 0) return 0;
    return sudoku_record_recv(conn->record, buf, len);
}

void sudoku_client_close(sudoku_client_conn_t *conn) {
    if (!conn) return;
    sudoku_record_conn_free(conn->record);
    sudoku_transport_close(conn->transport);
    sudoku_table_pair_free(&conn->tables);
    free(conn);
}

int sudoku_client_connect_uot(
    const sudoku_outbound_config_t *cfg,
    sudoku_uot_client_t **out_client
) {
    sudoku_uot_client_t *client;
    if (!cfg || !out_client) return -1;
    client = (sudoku_uot_client_t *)calloc(1, sizeof(*client));
    if (!client) return -1;
    if (sudoku_connect_base(cfg, &client->transport, &client->record, &client->tables) != 0) {
        free(client);
        return -1;
    }
    if (sudoku_start_uot(client->record) != 0) {
        sudoku_uot_client_close(client);
        return -1;
    }
    *out_client = client;
    return 0;
}

int sudoku_uot_sendto(
    sudoku_uot_client_t *client,
    const char *target_host,
    uint16_t target_port,
    const void *buf,
    size_t len
) {
    uint8_t addr[300];
    uint8_t hdr[4];
    size_t addr_len = 0;
    if (!client || !target_host || (!buf && len)) return -1;
    if (len > 65535) return -1;
    if (sudoku_write_address(addr, sizeof(addr), target_host, target_port, &addr_len) != 0) return -1;
    if (addr_len > 65535) return -1;
    hdr[0] = (uint8_t)(addr_len >> 8);
    hdr[1] = (uint8_t)addr_len;
    hdr[2] = (uint8_t)(len >> 8);
    hdr[3] = (uint8_t)len;
    if (sudoku_write_all_record(client->record, hdr, sizeof(hdr)) != 0) return -1;
    if (sudoku_write_all_record(client->record, addr, addr_len) != 0) return -1;
    if (len && sudoku_write_all_record(client->record, (const uint8_t *)buf, len) != 0) return -1;
    return 0;
}

ssize_t sudoku_uot_recvfrom(
    sudoku_uot_client_t *client,
    char *target_host,
    size_t target_host_cap,
    uint16_t *target_port,
    void *buf,
    size_t len
) {
    uint8_t hdr[4];
    uint8_t *addr = NULL;
    uint8_t *payload = NULL;
    uint16_t addr_len;
    uint16_t payload_len;
    size_t copy_len;
    ssize_t result = -1;
    if (!client || !target_host || target_host_cap == 0 || !target_port || (!buf && len)) return -1;
    if (sudoku_read_exact_record(client->record, hdr, sizeof(hdr)) != 0) goto done;
    addr_len = (uint16_t)(((uint16_t)hdr[0] << 8) | hdr[1]);
    payload_len = (uint16_t)(((uint16_t)hdr[2] << 8) | hdr[3]);
    if (addr_len == 0) goto done;
    addr = (uint8_t *)malloc(addr_len);
    payload = (uint8_t *)malloc(payload_len ? payload_len : 1);
    if (!addr || !payload) goto done;
    if (sudoku_read_exact_record(client->record, addr, addr_len) != 0) goto done;
    if (payload_len && sudoku_read_exact_record(client->record, payload, payload_len) != 0) goto done;
    if (sudoku_read_address(addr, addr_len, target_host, target_host_cap, target_port, NULL) != 0) goto done;
    copy_len = payload_len;
    if (copy_len > len) copy_len = len;
    if (copy_len) memcpy(buf, payload, copy_len);
    result = (ssize_t)payload_len;
done:
    free(addr);
    free(payload);
    return result;
}

void sudoku_uot_client_close(sudoku_uot_client_t *client) {
    if (!client) return;
    sudoku_record_conn_free(client->record);
    sudoku_transport_close(client->transport);
    sudoku_table_pair_free(&client->tables);
    free(client);
}

static void sudoku_mux_chunk_free_all(sudoku_mux_chunk_t *chunk) {
    while (chunk) {
        sudoku_mux_chunk_t *next = chunk->next;
        free(chunk->data);
        free(chunk);
        chunk = next;
    }
}

static struct sudoku_mux_stream *sudoku_mux_find_stream_locked(sudoku_mux_client_t *client, uint32_t id) {
    struct sudoku_mux_stream *cur = NULL;
    if (!client) return NULL;
    cur = client->streams;
    while (cur) {
        if (cur->id == id) {
            return cur;
        }
        cur = cur->next;
    }
    return NULL;
}

static void sudoku_mux_retire_stream_locked(sudoku_mux_client_t *client, struct sudoku_mux_stream *stream) {
    struct sudoku_mux_stream **link;
    if (!client || !stream || stream->removed) return;
    link = &client->streams;
    while (*link) {
        if (*link == stream) {
            *link = stream->next;
            stream->next = client->retired_streams;
            client->retired_streams = stream;
            stream->removed = 1;
            return;
        }
        link = &(*link)->next;
    }
    stream->removed = 1;
}

static void sudoku_mux_stream_mark_closed(struct sudoku_mux_stream *stream) {
    if (!stream) return;
    pthread_mutex_lock(&stream->mu);
    if (!stream->closed) {
        stream->closed = 1;
    }
    pthread_cond_broadcast(&stream->cond);
    pthread_mutex_unlock(&stream->mu);
}

static void sudoku_mux_client_mark_closed(sudoku_mux_client_t *client) {
    struct sudoku_mux_stream *cur;
    if (!client) return;
    pthread_mutex_lock(&client->mu);
    if (!client->closed) {
        client->closed = 1;
    }
    cur = client->streams;
    while (cur) {
        sudoku_mux_stream_mark_closed(cur);
        cur = cur->next;
    }
    pthread_mutex_unlock(&client->mu);
}

static int sudoku_mux_send_frame(
    sudoku_mux_client_t *client,
    uint8_t frame_type,
    uint32_t stream_id,
    const uint8_t *payload,
    uint32_t payload_len
) {
    uint8_t hdr[9];
    if (!client) return -1;
    if (payload_len > SUDOKU_MUX_MAX_FRAME_SIZE) return -1;
    hdr[0] = frame_type;
    hdr[1] = (uint8_t)(stream_id >> 24);
    hdr[2] = (uint8_t)(stream_id >> 16);
    hdr[3] = (uint8_t)(stream_id >> 8);
    hdr[4] = (uint8_t)stream_id;
    hdr[5] = (uint8_t)(payload_len >> 24);
    hdr[6] = (uint8_t)(payload_len >> 16);
    hdr[7] = (uint8_t)(payload_len >> 8);
    hdr[8] = (uint8_t)payload_len;
    pthread_mutex_lock(&client->write_mu);
    if (sudoku_write_all_record(client->record, hdr, sizeof(hdr)) != 0) {
        pthread_mutex_unlock(&client->write_mu);
        return -1;
    }
    if (payload_len && sudoku_write_all_record(client->record, payload, payload_len) != 0) {
        pthread_mutex_unlock(&client->write_mu);
        return -1;
    }
    pthread_mutex_unlock(&client->write_mu);
    return 0;
}

static int sudoku_mux_stream_enqueue(struct sudoku_mux_stream *stream, const uint8_t *payload, size_t payload_len) {
    sudoku_mux_chunk_t *chunk;
    if (!stream || (!payload && payload_len)) return -1;
    chunk = (sudoku_mux_chunk_t *)calloc(1, sizeof(*chunk));
    if (!chunk) return -1;
    chunk->data = (uint8_t *)malloc(payload_len ? payload_len : 1);
    if (!chunk->data) {
        free(chunk);
        return -1;
    }
    if (payload_len) memcpy(chunk->data, payload, payload_len);
    chunk->len = payload_len;
    pthread_mutex_lock(&stream->mu);
    if (stream->closed) {
        pthread_mutex_unlock(&stream->mu);
        free(chunk->data);
        free(chunk);
        return 0;
    }
    if (stream->tail) stream->tail->next = chunk;
    else stream->head = chunk;
    stream->tail = chunk;
    pthread_cond_signal(&stream->cond);
    pthread_mutex_unlock(&stream->mu);
    return 0;
}

static void *sudoku_mux_reader_main(void *opaque) {
    sudoku_mux_client_t *client = (sudoku_mux_client_t *)opaque;
    for (;;) {
        uint8_t hdr[9];
        uint8_t *payload = NULL;
        uint8_t frame_type;
        uint32_t stream_id;
        uint32_t payload_len;
        struct sudoku_mux_stream *stream = NULL;
        if (sudoku_read_exact_record(client->record, hdr, sizeof(hdr)) != 0) {
            sudoku_mux_client_mark_closed(client);
            return NULL;
        }
        frame_type = hdr[0];
        stream_id = ((uint32_t)hdr[1] << 24) | ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 8) | (uint32_t)hdr[4];
        payload_len = ((uint32_t)hdr[5] << 24) | ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 8) | (uint32_t)hdr[8];
        if (payload_len > SUDOKU_MUX_MAX_FRAME_SIZE) {
            sudoku_mux_client_mark_closed(client);
            return NULL;
        }
        if (payload_len > 0) {
            payload = (uint8_t *)malloc(payload_len);
            if (!payload) {
                sudoku_mux_client_mark_closed(client);
                return NULL;
            }
            if (sudoku_read_exact_record(client->record, payload, payload_len) != 0) {
                free(payload);
                sudoku_mux_client_mark_closed(client);
                return NULL;
            }
        }

        pthread_mutex_lock(&client->mu);
        stream = sudoku_mux_find_stream_locked(client, stream_id);
        if (stream && (frame_type == 0x03 || frame_type == 0x04)) {
            sudoku_mux_retire_stream_locked(client, stream);
        }
        pthread_mutex_unlock(&client->mu);

        if (frame_type == 0x02) {
            if (stream) {
                if (sudoku_mux_stream_enqueue(stream, payload, payload_len) != 0) {
                    free(payload);
                    sudoku_mux_client_mark_closed(client);
                    return NULL;
                }
            }
        } else if (frame_type == 0x03) {
            if (stream) {
                sudoku_mux_stream_mark_closed(stream);
            }
        } else if (frame_type == 0x04) {
            if (stream) {
                sudoku_mux_stream_mark_closed(stream);
            }
        } else {
            free(payload);
            sudoku_mux_client_mark_closed(client);
            return NULL;
        }
        free(payload);
    }
}

int sudoku_mux_client_open(
    const sudoku_outbound_config_t *cfg,
    sudoku_mux_client_t **out_client
) {
    sudoku_mux_client_t *client;
    if (!cfg || !out_client) return -1;
    client = (sudoku_mux_client_t *)calloc(1, sizeof(*client));
    if (!client) return -1;
    pthread_mutex_init(&client->mu, NULL);
    pthread_mutex_init(&client->write_mu, NULL);
    if (sudoku_connect_base(cfg, &client->transport, &client->record, &client->tables) != 0) {
        sudoku_mux_client_close(client);
        return -1;
    }
    if (sudoku_start_mux(client->record) != 0) {
        sudoku_mux_client_close(client);
        return -1;
    }
    if (pthread_create(&client->reader_thread, NULL, sudoku_mux_reader_main, client) != 0) {
        sudoku_mux_client_close(client);
        return -1;
    }
    client->reader_started = 1;
    *out_client = client;
    return 0;
}

int sudoku_mux_client_dial_tcp(
    sudoku_mux_client_t *client,
    const char *target_host,
    uint16_t target_port,
    sudoku_mux_stream_t **out_stream
) {
    sudoku_mux_stream_t *stream;
    uint8_t addr[300];
    size_t addr_len = 0;
    if (!client || !target_host || !target_port || !out_stream) return -1;
    if (sudoku_write_address(addr, sizeof(addr), target_host, target_port, &addr_len) != 0) return -1;
    stream = (sudoku_mux_stream_t *)calloc(1, sizeof(*stream));
    if (!stream) return -1;
    stream->client = client;
    pthread_mutex_init(&stream->mu, NULL);
    pthread_cond_init(&stream->cond, NULL);

    pthread_mutex_lock(&client->mu);
    if (client->closed) {
        pthread_mutex_unlock(&client->mu);
        pthread_cond_destroy(&stream->cond);
        pthread_mutex_destroy(&stream->mu);
        free(stream);
        return -1;
    }
    client->next_stream_id++;
    if (client->next_stream_id == 0) client->next_stream_id++;
    stream->id = client->next_stream_id;
    stream->next = client->streams;
    client->streams = stream;
    pthread_mutex_unlock(&client->mu);

    if (sudoku_mux_send_frame(client, 0x01, stream->id, addr, (uint32_t)addr_len) != 0) {
        sudoku_mux_stream_close(stream);
        return -1;
    }
    *out_stream = stream;
    return 0;
}

ssize_t sudoku_mux_stream_send(sudoku_mux_stream_t *stream, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    if (!stream || (!buf && len)) return -1;
    pthread_mutex_lock(&stream->mu);
    if (stream->closed) {
        pthread_mutex_unlock(&stream->mu);
        return -1;
    }
    pthread_mutex_unlock(&stream->mu);
    while (sent < len) {
        uint32_t chunk = (uint32_t)(len - sent);
        if (chunk > SUDOKU_MUX_MAX_DATA_PAYLOAD) chunk = SUDOKU_MUX_MAX_DATA_PAYLOAD;
        if (sudoku_mux_send_frame(stream->client, 0x02, stream->id, p + sent, chunk) != 0) {
            return sent ? (ssize_t)sent : -1;
        }
        sent += chunk;
    }
    return (ssize_t)sent;
}

ssize_t sudoku_mux_stream_recv(sudoku_mux_stream_t *stream, void *buf, size_t len) {
    sudoku_mux_chunk_t *chunk;
    size_t copy_len;
    if (!stream || !buf || len == 0) return -1;
    pthread_mutex_lock(&stream->mu);
    while (!stream->head && !stream->closed) {
        pthread_cond_wait(&stream->cond, &stream->mu);
    }
    chunk = stream->head;
    if (!chunk && stream->closed) {
        pthread_mutex_unlock(&stream->mu);
        return 0;
    }
    copy_len = chunk->len - chunk->off;
    if (copy_len > len) copy_len = len;
    memcpy(buf, chunk->data + chunk->off, copy_len);
    chunk->off += copy_len;
    if (chunk->off == chunk->len) {
        stream->head = chunk->next;
        if (!stream->head) stream->tail = NULL;
        free(chunk->data);
        free(chunk);
    }
    pthread_mutex_unlock(&stream->mu);
    return (ssize_t)copy_len;
}

void sudoku_mux_stream_close(sudoku_mux_stream_t *stream) {
    sudoku_mux_client_t *client;
    sudoku_mux_chunk_t *chunks = NULL;
    int should_send_fin = 0;
    if (!stream) return;
    client = stream->client;
    if (client) {
        pthread_mutex_lock(&client->mu);
        if (!stream->removed) {
            sudoku_mux_retire_stream_locked(client, stream);
            should_send_fin = !client->closed;
        }
        pthread_mutex_unlock(&client->mu);
        if (should_send_fin) {
            (void)sudoku_mux_send_frame(client, 0x03, stream->id, NULL, 0);
        }
    }
    sudoku_mux_stream_mark_closed(stream);
    pthread_mutex_lock(&stream->mu);
    chunks = stream->head;
    stream->head = NULL;
    stream->tail = NULL;
    pthread_mutex_unlock(&stream->mu);
    sudoku_mux_chunk_free_all(chunks);
}

void sudoku_mux_client_close(sudoku_mux_client_t *client) {
    struct sudoku_mux_stream *stream;
    struct sudoku_mux_stream *next;
    if (!client) return;
    sudoku_mux_client_mark_closed(client);
    if (client->transport) sudoku_transport_interrupt(client->transport);
    if (client->reader_started) {
        pthread_join(client->reader_thread, NULL);
        client->reader_started = 0;
    }
    if (client->record) {
        sudoku_record_conn_free(client->record);
        client->record = NULL;
    }
    if (client->transport) {
        sudoku_transport_close(client->transport);
        client->transport = NULL;
    }
    stream = client->streams;
    while (stream) {
        next = stream->next;
        sudoku_mux_chunk_free_all(stream->head);
        pthread_cond_destroy(&stream->cond);
        pthread_mutex_destroy(&stream->mu);
        free(stream);
        stream = next;
    }
    stream = client->retired_streams;
    while (stream) {
        next = stream->next;
        sudoku_mux_chunk_free_all(stream->head);
        pthread_cond_destroy(&stream->cond);
        pthread_mutex_destroy(&stream->mu);
        free(stream);
        stream = next;
    }
    sudoku_table_pair_free(&client->tables);
    pthread_mutex_destroy(&client->write_mu);
    pthread_mutex_destroy(&client->mu);
    free(client);
}
