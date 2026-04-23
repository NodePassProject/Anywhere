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

#include "SudokuSwiftBridge.h"

static sudoku_swift_aead_encrypt_fn sudoku_swift_aead_encrypt_cb = NULL;
static sudoku_swift_aead_decrypt_fn sudoku_swift_aead_decrypt_cb = NULL;
static sudoku_swift_x25519_generate_fn sudoku_swift_x25519_generate_cb = NULL;
static sudoku_swift_x25519_shared_fn sudoku_swift_x25519_shared_cb = NULL;

void sudoku_swift_set_crypto_callbacks(
    sudoku_swift_aead_encrypt_fn aead_encrypt,
    sudoku_swift_aead_decrypt_fn aead_decrypt,
    sudoku_swift_x25519_generate_fn x25519_generate,
    sudoku_swift_x25519_shared_fn x25519_shared
) {
    sudoku_swift_aead_encrypt_cb = aead_encrypt;
    sudoku_swift_aead_decrypt_cb = aead_decrypt;
    sudoku_swift_x25519_generate_cb = x25519_generate;
    sudoku_swift_x25519_shared_cb = x25519_shared;
}

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
) {
    if (!sudoku_swift_aead_encrypt_cb) return -1;
    return sudoku_swift_aead_encrypt_cb(
        dest,
        key,
        key_len,
        nonce,
        nonce_len,
        plaintext,
        plaintext_len,
        aad,
        aad_len,
        aead_kind
    );
}

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
) {
    if (!sudoku_swift_aead_decrypt_cb) return -1;
    return sudoku_swift_aead_decrypt_cb(
        dest,
        key,
        key_len,
        nonce,
        nonce_len,
        ciphertext,
        ciphertext_len,
        aad,
        aad_len,
        aead_kind
    );
}

int sudoku_swift_crypto_x25519_generate(uint8_t *private_key, uint8_t *public_key) {
    if (!sudoku_swift_x25519_generate_cb) return -1;
    return sudoku_swift_x25519_generate_cb(private_key, public_key);
}

int sudoku_swift_crypto_x25519_shared(
    const uint8_t *private_key,
    const uint8_t *peer_public_key,
    uint8_t *shared_key
) {
    if (!sudoku_swift_x25519_shared_cb) return -1;
    return sudoku_swift_x25519_shared_cb(private_key, peer_public_key, shared_key);
}

int sudoku_swift_client_connect_tcp(
    const sudoku_outbound_config_t *cfg,
    const char *target_host,
    uint16_t target_port,
    sudoku_tcp_handle_t *out_handle
) {
    sudoku_client_conn_t *conn = NULL;
    if (sudoku_client_connect_tcp(cfg, target_host, target_port, &conn) != 0) {
        return -1;
    }
    if (out_handle) {
        *out_handle = (sudoku_tcp_handle_t)conn;
    }
    return 0;
}

ssize_t sudoku_swift_client_send(sudoku_tcp_handle_t handle, const void *buf, size_t len) {
    if (!handle) return -1;
    return sudoku_client_send((sudoku_client_conn_t *)handle, buf, len);
}

ssize_t sudoku_swift_client_recv(sudoku_tcp_handle_t handle, void *buf, size_t len) {
    if (!handle) return -1;
    return sudoku_client_recv((sudoku_client_conn_t *)handle, buf, len);
}

void sudoku_swift_client_close(sudoku_tcp_handle_t handle) {
    if (!handle) return;
    sudoku_client_close((sudoku_client_conn_t *)handle);
}

int sudoku_swift_client_connect_uot(
    const sudoku_outbound_config_t *cfg,
    sudoku_uot_handle_t *out_handle
) {
    sudoku_uot_client_t *client = NULL;
    if (sudoku_client_connect_uot(cfg, &client) != 0) {
        return -1;
    }
    if (out_handle) {
        *out_handle = (sudoku_uot_handle_t)client;
    }
    return 0;
}

int sudoku_swift_uot_sendto(
    sudoku_uot_handle_t handle,
    const char *target_host,
    uint16_t target_port,
    const void *buf,
    size_t len
) {
    if (!handle) return -1;
    return sudoku_uot_sendto((sudoku_uot_client_t *)handle, target_host, target_port, buf, len);
}

ssize_t sudoku_swift_uot_recvfrom(
    sudoku_uot_handle_t handle,
    char *target_host,
    size_t target_host_cap,
    uint16_t *target_port,
    void *buf,
    size_t len
) {
    if (!handle) return -1;
    return sudoku_uot_recvfrom(
        (sudoku_uot_client_t *)handle,
        target_host,
        target_host_cap,
        target_port,
        buf,
        len
    );
}

void sudoku_swift_uot_close(sudoku_uot_handle_t handle) {
    if (!handle) return;
    sudoku_uot_client_close((sudoku_uot_client_t *)handle);
}

int sudoku_swift_mux_client_open(
    const sudoku_outbound_config_t *cfg,
    sudoku_mux_handle_t *out_handle
) {
    sudoku_mux_client_t *client = NULL;
    if (sudoku_mux_client_open(cfg, &client) != 0) {
        return -1;
    }
    if (out_handle) {
        *out_handle = (sudoku_mux_handle_t)client;
    }
    return 0;
}

int sudoku_swift_mux_dial_tcp(
    sudoku_mux_handle_t handle,
    const char *target_host,
    uint16_t target_port,
    sudoku_mux_stream_handle_t *out_stream
) {
    sudoku_mux_stream_t *stream = NULL;
    if (!handle) return -1;
    if (sudoku_mux_client_dial_tcp((sudoku_mux_client_t *)handle, target_host, target_port, &stream) != 0) {
        return -1;
    }
    if (out_stream) {
        *out_stream = (sudoku_mux_stream_handle_t)stream;
    }
    return 0;
}

ssize_t sudoku_swift_mux_stream_send(sudoku_mux_stream_handle_t stream, const void *buf, size_t len) {
    if (!stream) return -1;
    return sudoku_mux_stream_send((sudoku_mux_stream_t *)stream, buf, len);
}

ssize_t sudoku_swift_mux_stream_recv(sudoku_mux_stream_handle_t stream, void *buf, size_t len) {
    if (!stream) return -1;
    return sudoku_mux_stream_recv((sudoku_mux_stream_t *)stream, buf, len);
}

void sudoku_swift_mux_stream_close(sudoku_mux_stream_handle_t stream) {
    if (!stream) return;
    sudoku_mux_stream_close((sudoku_mux_stream_t *)stream);
}

void sudoku_swift_mux_client_close(sudoku_mux_handle_t handle) {
    if (!handle) return;
    sudoku_mux_client_close((sudoku_mux_client_t *)handle);
}
