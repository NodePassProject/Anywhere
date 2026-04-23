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

#ifdef __cplusplus
}
#endif

#endif
