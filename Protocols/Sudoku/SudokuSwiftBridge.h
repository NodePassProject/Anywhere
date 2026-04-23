/*
Copyright (C) 2026 by saba <contact me via issue>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
*/

#ifndef SUDOKU_SWIFT_BRIDGE_H
#define SUDOKU_SWIFT_BRIDGE_H

#include "SudokuOutbound.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void *sudoku_tcp_handle_t;
typedef void *sudoku_uot_handle_t;
typedef void *sudoku_mux_handle_t;
typedef void *sudoku_mux_stream_handle_t;

enum {
    SUDOKU_SWIFT_AEAD_AES128_GCM = 0,
    SUDOKU_SWIFT_AEAD_CHACHA20_POLY1305 = 1
};

typedef int (*sudoku_swift_aead_encrypt_fn)(
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

typedef int (*sudoku_swift_aead_decrypt_fn)(
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

typedef int (*sudoku_swift_x25519_generate_fn)(uint8_t *private_key, uint8_t *public_key);
typedef int (*sudoku_swift_x25519_shared_fn)(
    const uint8_t *private_key,
    const uint8_t *peer_public_key,
    uint8_t *shared_key
);

void sudoku_swift_set_crypto_callbacks(
    sudoku_swift_aead_encrypt_fn aead_encrypt,
    sudoku_swift_aead_decrypt_fn aead_decrypt,
    sudoku_swift_x25519_generate_fn x25519_generate,
    sudoku_swift_x25519_shared_fn x25519_shared
);

int sudoku_swift_crypto_aead_encrypt(
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

int sudoku_swift_crypto_aead_decrypt(
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

int sudoku_swift_crypto_x25519_generate(uint8_t *private_key, uint8_t *public_key);
int sudoku_swift_crypto_x25519_shared(
    const uint8_t *private_key,
    const uint8_t *peer_public_key,
    uint8_t *shared_key
);

int sudoku_swift_socket_factory_open_ex(
    void *ctx,
    const char *host,
    uint16_t port,
    int use_tls,
    const char *server_name
);

int sudoku_swift_client_connect_tcp(
    const sudoku_outbound_config_t *cfg,
    const char *target_host,
    uint16_t target_port,
    sudoku_tcp_handle_t *out_handle
);

ssize_t sudoku_swift_client_send(sudoku_tcp_handle_t handle, const void *buf, size_t len);
ssize_t sudoku_swift_client_recv(sudoku_tcp_handle_t handle, void *buf, size_t len);
void sudoku_swift_client_close(sudoku_tcp_handle_t handle);

int sudoku_swift_client_connect_uot(
    const sudoku_outbound_config_t *cfg,
    sudoku_uot_handle_t *out_handle
);

int sudoku_swift_uot_sendto(
    sudoku_uot_handle_t handle,
    const char *target_host,
    uint16_t target_port,
    const void *buf,
    size_t len
);

ssize_t sudoku_swift_uot_recvfrom(
    sudoku_uot_handle_t handle,
    char *target_host,
    size_t target_host_cap,
    uint16_t *target_port,
    void *buf,
    size_t len
);

void sudoku_swift_uot_close(sudoku_uot_handle_t handle);

int sudoku_swift_mux_client_open(
    const sudoku_outbound_config_t *cfg,
    sudoku_mux_handle_t *out_handle
);

int sudoku_swift_mux_dial_tcp(
    sudoku_mux_handle_t handle,
    const char *target_host,
    uint16_t target_port,
    sudoku_mux_stream_handle_t *out_stream
);

ssize_t sudoku_swift_mux_stream_send(sudoku_mux_stream_handle_t stream, const void *buf, size_t len);
ssize_t sudoku_swift_mux_stream_recv(sudoku_mux_stream_handle_t stream, void *buf, size_t len);
void sudoku_swift_mux_stream_close(sudoku_mux_stream_handle_t stream);
void sudoku_swift_mux_client_close(sudoku_mux_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif
