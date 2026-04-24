#ifndef SUDOKU_KEY_H
#define SUDOKU_KEY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int sudoku_recover_public_key_hex(const char *key_hex, char public_key_hex[65]);

#ifdef __cplusplus
}
#endif

#endif
