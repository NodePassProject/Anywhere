#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include "blake3.h"
#include "blake3_impl.h"

const char *blake3_version(void) { return BLAKE3_VERSION_STRING; }

INLINE void chunk_state_init(blake3_chunk_state *self, const uint32_t key[8],
                             uint8_t flags) {
  memcpy(self->cv, key, BLAKE3_KEY_LEN);
  self->chunk_counter = 0;
  memset(self->buf, 0, BLAKE3_BLOCK_LEN);
  self->buf_len = 0;
  self->blocks_compressed = 0;
  self->flags = flags;
}

INLINE void chunk_state_reset(blake3_chunk_state *self, const uint32_t key[8],
                              uint64_t chunk_counter) {
  memcpy(self->cv, key, BLAKE3_KEY_LEN);
  self->chunk_counter = chunk_counter;
  self->blocks_compressed = 0;
  memset(self->buf, 0, BLAKE3_BLOCK_LEN);
  self->buf_len = 0;
}

INLINE size_t chunk_state_len(const blake3_chunk_state *self) {
  return (BLAKE3_BLOCK_LEN * (size_t)self->blocks_compressed) +
         ((size_t)self->buf_len);
}

INLINE size_t chunk_state_fill_buf(blake3_chunk_state *self,
                                   const uint8_t *input, size_t input_len) {
  size_t take = BLAKE3_BLOCK_LEN - ((size_t)self->buf_len);
  if (take > input_len) {
    take = input_len;
  }
  uint8_t *dest = self->buf + ((size_t)self->buf_len);
  memcpy(dest, input, take);
  self->buf_len += (uint8_t)take;
  return take;
}

INLINE uint8_t chunk_state_maybe_start_flag(const blake3_chunk_state *self) {
  if (self->blocks_compressed == 0) {
    return CHUNK_START;
  } else {
    return 0;
  }
}

typedef struct {
  uint32_t input_cv[8];
  uint64_t counter;
  uint8_t block[BLAKE3_BLOCK_LEN];
  uint8_t block_len;
  uint8_t flags;
} output_t;

INLINE output_t make_output(const uint32_t input_cv[8],
                            const uint8_t block[BLAKE3_BLOCK_LEN],
                            uint8_t block_len, uint64_t counter,
                            uint8_t flags) {
  output_t ret;
  memcpy(ret.input_cv, input_cv, 32);
  memcpy(ret.block, block, BLAKE3_BLOCK_LEN);
  ret.block_len = block_len;
  ret.counter = counter;
  ret.flags = flags;
  return ret;
}

INLINE void output_chaining_value(const output_t *self, uint8_t cv[32]) {
  uint32_t cv_words[8];
  memcpy(cv_words, self->input_cv, 32);
  blake3_compress_in_place(cv_words, self->block, self->block_len,
                           self->counter, self->flags);
  store_cv_words(cv, cv_words);
}

INLINE void output_root_bytes(const output_t *self, uint64_t seek, uint8_t *out,
                              size_t out_len) {
  if (out_len == 0) {
      return;
  }
  uint64_t output_block_counter = seek / 64;
  size_t offset_within_block = seek % 64;
  uint8_t wide_buf[64];
  if(offset_within_block) {
    blake3_compress_xof(self->input_cv, self->block, self->block_len, output_block_counter, self->flags | ROOT, wide_buf);
    const size_t available_bytes = 64 - offset_within_block;
    const size_t bytes = out_len > available_bytes ? available_bytes : out_len;
    memcpy(out, wide_buf + offset_within_block, bytes);
    out += bytes;
    out_len -= bytes;
    output_block_counter += 1;
  }
  if(out_len / 64) {
    blake3_xof_many(self->input_cv, self->block, self->block_len, output_block_counter, self->flags | ROOT, out, out_len / 64);
  }
  output_block_counter += out_len / 64;
  out += out_len & ~(size_t)63;
  out_len -= out_len & ~(size_t)63;
  if(out_len) {
    blake3_compress_xof(self->input_cv, self->block, self->block_len, output_block_counter, self->flags | ROOT, wide_buf);
    memcpy(out, wide_buf, out_len);
  }
}

INLINE void chunk_state_update(blake3_chunk_state *self, const uint8_t *input,
                               size_t input_len) {
  if (self->buf_len > 0) {
    size_t take = chunk_state_fill_buf(self, input, input_len);
    input += take;
    input_len -= take;
    if (input_len > 0) {
      blake3_compress_in_place(
          self->cv, self->buf, BLAKE3_BLOCK_LEN, self->chunk_counter,
          self->flags | chunk_state_maybe_start_flag(self));
      self->blocks_compressed += 1;
      self->buf_len = 0;
      memset(self->buf, 0, BLAKE3_BLOCK_LEN);
    }
  }

  while (input_len > BLAKE3_BLOCK_LEN) {
    blake3_compress_in_place(self->cv, input, BLAKE3_BLOCK_LEN,
                             self->chunk_counter,
                             self->flags | chunk_state_maybe_start_flag(self));
    self->blocks_compressed += 1;
    input += BLAKE3_BLOCK_LEN;
    input_len -= BLAKE3_BLOCK_LEN;
  }

  chunk_state_fill_buf(self, input, input_len);
}

INLINE output_t chunk_state_output(const blake3_chunk_state *self) {
  uint8_t block_flags =
      self->flags | chunk_state_maybe_start_flag(self) | CHUNK_END;
  return make_output(self->cv, self->buf, self->buf_len, self->chunk_counter,
                     block_flags);
}

INLINE output_t parent_output(const uint8_t block[BLAKE3_BLOCK_LEN],
                              const uint32_t key[8], uint8_t flags) {
  return make_output(key, block, BLAKE3_BLOCK_LEN, 0, flags | PARENT);
}

INLINE size_t left_subtree_len(size_t input_len) {
  size_t full_chunks = (input_len - 1) / BLAKE3_CHUNK_LEN;
  return round_down_to_power_of_2(full_chunks) * BLAKE3_CHUNK_LEN;
}

INLINE size_t compress_chunks_parallel(const uint8_t *input, size_t input_len,
                                       const uint32_t key[8],
                                       uint64_t chunk_counter, uint8_t flags,
                                       uint8_t *out) {
  const uint8_t *chunks_array[MAX_SIMD_DEGREE];
  size_t input_position = 0;
  size_t chunks_array_len = 0;
  while (input_len - input_position >= BLAKE3_CHUNK_LEN) {
    chunks_array[chunks_array_len] = &input[input_position];
    input_position += BLAKE3_CHUNK_LEN;
    chunks_array_len += 1;
  }

  blake3_hash_many(chunks_array, chunks_array_len,
                   BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, key, chunk_counter,
                   true, flags, CHUNK_START, CHUNK_END, out);

  if (input_len > input_position) {
    uint64_t counter = chunk_counter + (uint64_t)chunks_array_len;
    blake3_chunk_state chunk_state;
    chunk_state_init(&chunk_state, key, flags);
    chunk_state.chunk_counter = counter;
    chunk_state_update(&chunk_state, &input[input_position],
                       input_len - input_position);
    output_t output = chunk_state_output(&chunk_state);
    output_chaining_value(&output, &out[chunks_array_len * BLAKE3_OUT_LEN]);
    return chunks_array_len + 1;
  } else {
    return chunks_array_len;
  }
}

INLINE size_t compress_parents_parallel(const uint8_t *child_chaining_values,
                                        size_t num_chaining_values,
                                        const uint32_t key[8], uint8_t flags,
                                        uint8_t *out) {
  const uint8_t *parents_array[MAX_SIMD_DEGREE_OR_2];
  size_t parents_array_len = 0;
  while (num_chaining_values - (2 * parents_array_len) >= 2) {
    parents_array[parents_array_len] =
        &child_chaining_values[2 * parents_array_len * BLAKE3_OUT_LEN];
    parents_array_len += 1;
  }

  blake3_hash_many(parents_array, parents_array_len, 1, key,
                   0, // Parents always use counter 0.
                   false, flags | PARENT,
                   0, // Parents have no start flags.
                   0, // Parents have no end flags.
                   out);

  if (num_chaining_values > 2 * parents_array_len) {
    memcpy(&out[parents_array_len * BLAKE3_OUT_LEN],
           &child_chaining_values[2 * parents_array_len * BLAKE3_OUT_LEN],
           BLAKE3_OUT_LEN);
    return parents_array_len + 1;
  } else {
    return parents_array_len;
  }
}

size_t blake3_compress_subtree_wide(const uint8_t *input, size_t input_len,
                                    const uint32_t key[8],
                                    uint64_t chunk_counter, uint8_t flags,
                                    uint8_t *out, bool use_tbb) {
  (void)use_tbb;
  if (input_len <= blake3_simd_degree() * BLAKE3_CHUNK_LEN) {
    return compress_chunks_parallel(input, input_len, key, chunk_counter, flags,
                                    out);
  }

  size_t left_input_len = left_subtree_len(input_len);
  size_t right_input_len = input_len - left_input_len;
  const uint8_t *right_input = &input[left_input_len];
  uint64_t right_chunk_counter =
      chunk_counter + (uint64_t)(left_input_len / BLAKE3_CHUNK_LEN);

  uint8_t cv_array[2 * MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN];
  size_t degree = blake3_simd_degree();
  if (left_input_len > BLAKE3_CHUNK_LEN && degree == 1) {
    degree = 2;
  }
  uint8_t *right_cvs = &cv_array[degree * BLAKE3_OUT_LEN];

  size_t left_n = blake3_compress_subtree_wide(
      input, left_input_len, key, chunk_counter, flags, cv_array, use_tbb);
  size_t right_n = blake3_compress_subtree_wide(right_input, right_input_len, key,
                                         right_chunk_counter, flags, right_cvs,
                                         use_tbb);

  if (left_n == 1) {
    memcpy(out, cv_array, 2 * BLAKE3_OUT_LEN);
    return 2;
  }

  size_t num_chaining_values = left_n + right_n;
  return compress_parents_parallel(cv_array, num_chaining_values, key, flags,
                                   out);
}

INLINE void
compress_subtree_to_parent_node(const uint8_t *input, size_t input_len,
                                const uint32_t key[8], uint64_t chunk_counter,
                                uint8_t flags, uint8_t out[2 * BLAKE3_OUT_LEN],
                                bool use_tbb) {
  uint8_t cv_array[MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN];
  size_t num_cvs = blake3_compress_subtree_wide(input, input_len, key,
                                                chunk_counter, flags, cv_array, use_tbb);
  assert(num_cvs <= MAX_SIMD_DEGREE_OR_2);
  memcpy(out, cv_array, 2 * BLAKE3_OUT_LEN);
}

INLINE void hasher_init_base(blake3_hasher *self, const uint32_t key[8],
                             uint8_t flags) {
  memcpy(self->key, key, BLAKE3_KEY_LEN);
  chunk_state_init(&self->chunk, key, flags);
  self->cv_stack_len = 0;
}

void blake3_hasher_init(blake3_hasher *self) { hasher_init_base(self, IV, 0); }

void blake3_hasher_init_keyed(blake3_hasher *self,
                              const uint8_t key[BLAKE3_KEY_LEN]) {
  uint32_t key_words[8];
  load_key_words(key, key_words);
  hasher_init_base(self, key_words, KEYED_HASH);
}

void blake3_hasher_init_derive_key_raw(blake3_hasher *self, const void *context,
                                       size_t context_len) {
  blake3_hasher context_hasher;
  hasher_init_base(&context_hasher, IV, DERIVE_KEY_CONTEXT);
  blake3_hasher_update(&context_hasher, context, context_len);
  uint8_t context_key[BLAKE3_KEY_LEN];
  blake3_hasher_finalize(&context_hasher, context_key, BLAKE3_KEY_LEN);
  uint32_t context_key_words[8];
  load_key_words(context_key, context_key_words);
  hasher_init_base(self, context_key_words, DERIVE_KEY_MATERIAL);
}

void blake3_hasher_init_derive_key(blake3_hasher *self, const char *context) {
  blake3_hasher_init_derive_key_raw(self, context, strlen(context));
}

INLINE void hasher_merge_cv_stack(blake3_hasher *self, uint64_t total_len) {
  size_t post_merge_stack_len = (size_t)popcnt(total_len);
  while (self->cv_stack_len > post_merge_stack_len) {
    uint8_t *parent_node =
        &self->cv_stack[(self->cv_stack_len - 2) * BLAKE3_OUT_LEN];
    output_t output = parent_output(parent_node, self->key, self->chunk.flags);
    output_chaining_value(&output, parent_node);
    self->cv_stack_len -= 1;
  }
}

INLINE void hasher_push_cv(blake3_hasher *self, uint8_t new_cv[BLAKE3_OUT_LEN],
                           uint64_t chunk_counter) {
  hasher_merge_cv_stack(self, chunk_counter);
  memcpy(&self->cv_stack[self->cv_stack_len * BLAKE3_OUT_LEN], new_cv,
         BLAKE3_OUT_LEN);
  self->cv_stack_len += 1;
}

void blake3_hasher_update(blake3_hasher *self, const void *input,
                          size_t input_len) {
  if (input_len == 0) {
    return;
  }

  const uint8_t *input_bytes = (const uint8_t *)input;

  if (chunk_state_len(&self->chunk) > 0) {
    size_t take = BLAKE3_CHUNK_LEN - chunk_state_len(&self->chunk);
    if (take > input_len) {
      take = input_len;
    }
    chunk_state_update(&self->chunk, input_bytes, take);
    input_bytes += take;
    input_len -= take;
    if (input_len > 0) {
      output_t output = chunk_state_output(&self->chunk);
      uint8_t chunk_cv[32];
      output_chaining_value(&output, chunk_cv);
      hasher_push_cv(self, chunk_cv, self->chunk.chunk_counter);
      chunk_state_reset(&self->chunk, self->key, self->chunk.chunk_counter + 1);
    } else {
      return;
    }
  }

  while (input_len > BLAKE3_CHUNK_LEN) {
    size_t subtree_len = round_down_to_power_of_2(input_len);
    uint64_t count_so_far = self->chunk.chunk_counter * BLAKE3_CHUNK_LEN;
    while ((((uint64_t)(subtree_len - 1)) & count_so_far) != 0) {
      subtree_len /= 2;
    }
    uint64_t subtree_chunks = subtree_len / BLAKE3_CHUNK_LEN;
    if (subtree_len <= BLAKE3_CHUNK_LEN) {
      blake3_chunk_state chunk_state;
      chunk_state_init(&chunk_state, self->key, self->chunk.flags);
      chunk_state.chunk_counter = self->chunk.chunk_counter;
      chunk_state_update(&chunk_state, input_bytes, subtree_len);
      output_t output = chunk_state_output(&chunk_state);
      uint8_t cv[BLAKE3_OUT_LEN];
      output_chaining_value(&output, cv);
      hasher_push_cv(self, cv, chunk_state.chunk_counter);
    } else {
      uint8_t cv_pair[2 * BLAKE3_OUT_LEN];
      compress_subtree_to_parent_node(input_bytes, subtree_len, self->key,
                                      self->chunk.chunk_counter,
                                      self->chunk.flags, cv_pair, false);
      hasher_push_cv(self, cv_pair, self->chunk.chunk_counter);
      hasher_push_cv(self, &cv_pair[BLAKE3_OUT_LEN],
                     self->chunk.chunk_counter + (subtree_chunks / 2));
    }
    self->chunk.chunk_counter += subtree_chunks;
    input_bytes += subtree_len;
    input_len -= subtree_len;
  }

  if (input_len > 0) {
    chunk_state_update(&self->chunk, input_bytes, input_len);
    hasher_merge_cv_stack(self, self->chunk.chunk_counter);
  }
}

void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out,
                            size_t out_len) {
  blake3_hasher_finalize_seek(self, 0, out, out_len);
}

void blake3_hasher_finalize_seek(const blake3_hasher *self, uint64_t seek,
                                 uint8_t *out, size_t out_len) {
  if (out_len == 0) {
    return;
  }

  if (self->cv_stack_len == 0) {
    output_t output = chunk_state_output(&self->chunk);
    output_root_bytes(&output, seek, out, out_len);
    return;
  }

  output_t output;
  size_t cvs_remaining;
  if (chunk_state_len(&self->chunk) > 0) {
    cvs_remaining = self->cv_stack_len;
    output = chunk_state_output(&self->chunk);
  } else {
    cvs_remaining = self->cv_stack_len - 2;
    output = parent_output(&self->cv_stack[cvs_remaining * 32], self->key,
                           self->chunk.flags);
  }
  while (cvs_remaining > 0) {
    cvs_remaining -= 1;
    uint8_t parent_block[BLAKE3_BLOCK_LEN];
    memcpy(parent_block, &self->cv_stack[cvs_remaining * 32], 32);
    output_chaining_value(&output, &parent_block[32]);
    output = parent_output(parent_block, self->key, self->chunk.flags);
  }
  output_root_bytes(&output, seek, out, out_len);
}

void blake3_hasher_reset(blake3_hasher *self) {
  chunk_state_reset(&self->chunk, self->key, 0);
  self->cv_stack_len = 0;
}
