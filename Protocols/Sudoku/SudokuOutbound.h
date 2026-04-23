#ifndef SUDOKU_OUTBOUND_H
#define SUDOKU_OUTBOUND_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "SudokuCore.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SUDOKU_KEY_AUTO = 0,
    SUDOKU_KEY_PUBLIC = 1,
    SUDOKU_KEY_PRIVATE32 = 2,
    SUDOKU_KEY_PRIVATE64 = 3
} sudoku_key_kind_t;

typedef struct {
    char server_host[256];
    uint16_t server_port;

    char key_hex[129];
    sudoku_key_kind_t key_kind;

    char public_key_hex[65];
    uint8_t private_key[64];
    size_t private_key_len;

    char aead_method[32];
    char ascii_mode[64];
    int padding_min;
    int padding_max;
    int enable_pure_downlink;

    int httpmask_disable;
    char httpmask_mode[16];
    int httpmask_tls;
    char httpmask_host[256];
    char httpmask_path_root[64];
    char httpmask_multiplex[8];

    void *swift_socket_factory_ctx;
    size_t custom_tables_count;
    char custom_tables[16][16];
} sudoku_outbound_config_t;

typedef struct sudoku_client_conn sudoku_client_conn_t;
typedef struct sudoku_uot_client sudoku_uot_client_t;
typedef struct sudoku_mux_client sudoku_mux_client_t;
typedef struct sudoku_mux_stream sudoku_mux_stream_t;

void sudoku_outbound_config_init(sudoku_outbound_config_t *cfg);
int sudoku_outbound_config_finalize(sudoku_outbound_config_t *cfg);

int sudoku_client_connect_tcp(
    const sudoku_outbound_config_t *cfg,
    const char *target_host,
    uint16_t target_port,
    sudoku_client_conn_t **out_conn
);

ssize_t sudoku_client_send(sudoku_client_conn_t *conn, const void *buf, size_t len);
ssize_t sudoku_client_recv(sudoku_client_conn_t *conn, void *buf, size_t len);
void sudoku_client_close(sudoku_client_conn_t *conn);

int sudoku_client_connect_uot(
    const sudoku_outbound_config_t *cfg,
    sudoku_uot_client_t **out_client
);
int sudoku_uot_sendto(
    sudoku_uot_client_t *client,
    const char *target_host,
    uint16_t target_port,
    const void *buf,
    size_t len
);
ssize_t sudoku_uot_recvfrom(
    sudoku_uot_client_t *client,
    char *target_host,
    size_t target_host_cap,
    uint16_t *target_port,
    void *buf,
    size_t len
);
void sudoku_uot_client_close(sudoku_uot_client_t *client);

int sudoku_mux_client_open(
    const sudoku_outbound_config_t *cfg,
    sudoku_mux_client_t **out_client
);
int sudoku_mux_client_dial_tcp(
    sudoku_mux_client_t *client,
    const char *target_host,
    uint16_t target_port,
    sudoku_mux_stream_t **out_stream
);
ssize_t sudoku_mux_stream_send(sudoku_mux_stream_t *stream, const void *buf, size_t len);
ssize_t sudoku_mux_stream_recv(sudoku_mux_stream_t *stream, void *buf, size_t len);
void sudoku_mux_stream_close(sudoku_mux_stream_t *stream);
void sudoku_mux_client_close(sudoku_mux_client_t *client);

#ifdef __cplusplus
}
#endif

#endif
