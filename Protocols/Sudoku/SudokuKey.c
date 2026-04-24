#include "SudokuKey.h"
#include <string.h>
#include <stdlib.h>

#define SUDOKU_APPLE_SWIFT_BACKEND 1

static void sudoku_hex_encode_key(const uint8_t *src, size_t len, char *out) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = hex[src[i] >> 4];
        out[i * 2 + 1] = hex[src[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static int sudoku_hex_nibble_key(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int sudoku_hex_decode_key(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t len = strlen(hex);
    if ((len & 1u) != 0 || out_cap < len / 2) return -1;
    for (size_t i = 0; i < len; i += 2) {
        int hi = sudoku_hex_nibble_key(hex[i]);
        int lo = sudoku_hex_nibble_key(hex[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    if (out_len) *out_len = len / 2;
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


int sudoku_recover_public_key_hex(const char *key_hex, char public_key_hex[65]) {
    uint8_t raw[64];
    size_t raw_len = 0;
    uint8_t public_key[32];
    if (!key_hex || !public_key_hex) return -1;
    if (sudoku_hex_decode_key(key_hex, raw, sizeof(raw), &raw_len) != 0) return -1;
    if (raw_len == 32 && sudoku_key_is_public_point(raw, raw_len)) {
        sudoku_hex_encode_key(raw, 32, public_key_hex);
        return 0;
    }
    if (sudoku_public_key_from_private(raw, raw_len, public_key) != 0) return -1;
    sudoku_hex_encode_key(public_key, 32, public_key_hex);
    return 0;
}
