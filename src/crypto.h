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

#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <sodium.h>

#if SODIUM_LIBRARY_VERSION_MAJOR >= 8
#define CIPHER_NUM          21
#else
#define CIPHER_NUM          20
#endif

#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

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

typedef struct cipher_ctx cipher_ctx_t;
typedef struct cipher cipher_t;
typedef struct buffer buffer_t;
typedef struct crypto_ctx crypto_ctx_t;

typedef struct crypto {
    int method;

    int(*const parse_packet)(const char *, size_t, char **);
    int (*const encrypt_all)(buffer_t *, int, size_t);
    int (*const decrypt_all)(buffer_t *, int, size_t);
    int (*const encrypt)(buffer_t *, crypto_ctx_t*, size_t);
    int (*const decrypt)(buffer_t *, crypto_ctx_t*, size_t);

    void (*const ctx_init)(int, crypto_ctx_t*, int);
    int (*const init)(const char *, const char *);
    int (*const get_iv_len)(void);
    void (*const cipher_context_release)(cipher_ctx_t *);
} crypto_t;

int balloc(buffer_t *ptr, size_t capacity);
int brealloc(buffer_t *ptr, size_t len, size_t capacity);
void bfree(buffer_t *ptr);
int rand_bytes(void *output, int len);
int crypto_init(const char *password, const char *method);

#endif // _CRYPTO_H
