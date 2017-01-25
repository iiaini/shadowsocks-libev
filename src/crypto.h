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

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

/* Definations for mbedTLS */
#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
typedef mbedtls_cipher_info_t cipher_kt_t;
typedef mbedtls_cipher_context_t cipher_evp_t;
typedef mbedtls_md_info_t digest_type_t;
#define MAX_KEY_LENGTH 64
#define MAX_NONCE_LENGTH MBEDTLS_MAX_NONCE_LENGTH
#define MAX_MD_SIZE MBEDTLS_MD_MAX_SIZE
/* we must have MBEDTLS_CIPHER_MODE_CFB defined */
#if !defined(MBEDTLS_CIPHER_MODE_CFB)
#error Cipher Feedback mode a.k.a CFB not supported by your mbed TLS.
#endif
#ifndef MBEDTLS_GCM_C
#error No GCM support detected
#endif
#ifdef crypto_aead_xchacha20poly1305_ietf_ABYTES
#define FS_HAVE_XCHACHA20IETF
#endif

/* Definations for Appple CC*/
#ifdef USE_CRYPTO_APPLECC
#include <CommonCrypto/CommonCrypto.h>
#define kCCAlgorithmInvalid UINT32_MAX
#define kCCContextValid 0
#define kCCContextInvalid -1
typedef struct {
    CCCryptorRef cryptor;
    int valid;
    CCOperation encrypt;
    CCAlgorithm cipher;
    CCMode mode;
    CCPadding padding;
    uint8_t iv[MAX_NONCE_LENGTH];
    uint8_t key[MAX_KEY_LENGTH];
    size_t iv_len;
    size_t key_len;
} cipher_cc_t;
#endif

typedef struct {
    cipher_evp_t *evp;
#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t cc;
#endif
    uint8_t nonce[MAX_NONCE_LENGTH];
} cipher_ctx_t;

typedef struct {
    cipher_kt_t *info;
    size_t nonce_len;
    size_t key_len;
} cipher_t;

typedef struct crypto_ctx {
    uint8_t init;
    uint64_t counter; /* for sodium padding */
    cipher_ctx_t evp;
} crypto_ctx_t;

typedef struct crypto {
    int method;

    int (*const encrypt_all)(buffer_t *, int, size_t);
    int (*const decrypt_all)(buffer_t *, int, size_t);
    int (*const encrypt)(buffer_t *, crypto_ctx_t*, size_t);
    int (*const decrypt)(buffer_t *, crypto_ctx_t*, size_t);

    void (*const ctx_init)(int, crypto_ctx_t*, int);
    void (*const ctx_release)(crypto_ctx_t *);
} crypto_t;

int balloc(buffer_t *ptr, size_t capacity);
int brealloc(buffer_t *ptr, size_t len, size_t capacity);
void bfree(buffer_t *ptr);
int rand_bytes(void *output, int len);
int crypto_init(const char *password, const char *method);

extern const char *stream_supported_ciphers;
extern const char *aead_supported_ciphers;

#endif // _CRYPTO_H
