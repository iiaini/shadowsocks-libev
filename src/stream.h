/*
 * encrypt.h - Define the enryptor's interface
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _STREAM_H
#define _STREAM_H

#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <sodium.h>

#define SODIUM_BLOCK_SIZE   64

#define NONE                -1
#define TABLE               0
#define RC4                 1
#define RC4_MD5             2
#define AES_128_CFB         3
#define AES_192_CFB         4
#define AES_256_CFB         5
#define AES_128_CTR         6
#define AES_192_CTR         7
#define AES_256_CTR         8
#define BF_CFB              9
#define CAMELLIA_128_CFB    10
#define CAMELLIA_192_CFB    11
#define CAMELLIA_256_CFB    12
#define CAST5_CFB           13
#define DES_CFB             14
#define IDEA_CFB            15
#define RC2_CFB             16
#define SEED_CFB            17
#define SALSA20             18
#define CHACHA20            19
#define CHACHA20IETF        20

int stream_encrypt_all(buffer_t *plaintext, int method, size_t capacity);
int stream_decrypt_all(buffer_t *ciphertext, int method, size_t capacity);
int stream_encrypt(buffer_t *plaintext, crypto_ctx_t *ctx, size_t capacity);
int stream_decrypt(buffer_t *ciphertext, crypto_ctx_t *ctx, size_t capacity);

void stream_ctx_init(int method, crypto_ctx_t *ctx, int enc);
void stream_ctx_release(cipher_ctx_t *evp);

int stream_init(const char *pass, const char *method);
int stream_get_iv_len(void);

#endif // _STREAM_H
