#ifndef SUDOKU_CORE_H
#define SUDOKU_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *uplink_token;
    const char *downlink_token;
} sudoku_ascii_mode_t;

typedef struct {
    char name[32];
    uint8_t pad_marker;
    uint8_t padding_pool[64];
    size_t padding_pool_len;
    uint8_t encode_hint[4][16];
    uint8_t encode_group[64];
    uint8_t decode_group[256];
    uint8_t hint_table[256];
    uint8_t group_valid[256];
} sudoku_layout_t;

typedef struct {
    uint8_t cells[16];
} sudoku_grid_t;

typedef struct {
    uint8_t hints[4];
} sudoku_hint4_t;

typedef struct {
    sudoku_layout_t layout;
    sudoku_hint4_t *encode_table[256];
    uint16_t encode_count[256];
    uint32_t *decode_keys;
    uint8_t *decode_values;
    uint8_t *decode_used;
    size_t decode_cap;
    uint32_t hint;
    uint8_t is_ascii;
} sudoku_table_t;

typedef struct {
    sudoku_table_t uplink;
    sudoku_table_t downlink;
    uint8_t same_direction;
} sudoku_table_pair_t;

typedef struct {
    uint64_t state;
} sudoku_splitmix64_t;

typedef struct {
    uint8_t pending[8192];
    size_t pending_len;
    size_t pending_off;
    uint8_t hint_buf[4];
    int hint_count;
} sudoku_decoder_t;

typedef struct {
    uint8_t pending[8192];
    size_t pending_len;
    size_t pending_off;
    uint64_t bitbuf;
    int bitcount;
    uint8_t pad_marker;
} sudoku_packed_decoder_t;

int sudoku_parse_ascii_mode(const char *mode, sudoku_ascii_mode_t *out_mode);
int sudoku_table_pair_init(
    sudoku_table_pair_t *pair,
    const char *key,
    const char *ascii_mode,
    const char *custom_uplink,
    const char *custom_downlink
);
void sudoku_table_pair_free(sudoku_table_pair_t *pair);

void sudoku_splitmix64_seed(sudoku_splitmix64_t *rng, int64_t seed);
uint64_t sudoku_splitmix64_next_u64(sudoku_splitmix64_t *rng);
uint32_t sudoku_splitmix64_next_u32(sudoku_splitmix64_t *rng);
int sudoku_splitmix64_intn(sudoku_splitmix64_t *rng, int n);
uint64_t sudoku_pick_padding_threshold(sudoku_splitmix64_t *rng, int pmin, int pmax);
int sudoku_should_pad(sudoku_splitmix64_t *rng, uint64_t threshold);

size_t sudoku_encode_pure(
    uint8_t *dst,
    size_t dst_cap,
    const sudoku_table_t *table,
    sudoku_splitmix64_t *rng,
    uint64_t padding_threshold,
    const uint8_t *src,
    size_t src_len
);

void sudoku_decoder_init(sudoku_decoder_t *decoder);
size_t sudoku_decode_pure(
    sudoku_decoder_t *decoder,
    const sudoku_table_t *table,
    const uint8_t *src,
    size_t src_len,
    uint8_t *dst,
    size_t dst_cap,
    int *err
);

void sudoku_packed_decoder_init(sudoku_packed_decoder_t *decoder, const sudoku_table_t *table);
size_t sudoku_decode_packed(
    sudoku_packed_decoder_t *decoder,
    const sudoku_table_t *table,
    const uint8_t *src,
    size_t src_len,
    uint8_t *dst,
    size_t dst_cap,
    int *err
);

#ifdef __cplusplus
}
#endif

#endif
