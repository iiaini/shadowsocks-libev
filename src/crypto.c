/*
 * crypto.c - Manage the global crypto
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <sodium.h>

#include "crypto.h"
#include "stream.h"
#include "utils.h"

int
balloc(buffer_t *ptr, size_t capacity)
{
    sodium_memzero(ptr, sizeof(buffer_t));
    ptr->data    = ss_malloc(capacity);
    ptr->capacity = capacity;
    return capacity;
}

int
brealloc(buffer_t *ptr, size_t len, size_t capacity)
{
    if (ptr == NULL)
        return -1;
    size_t real_capacity = max(len, capacity);
    if (ptr->capacity < real_capacity) {
        ptr->data    = ss_realloc(ptr->data, real_capacity);
        ptr->capacity = real_capacity;
    }
    return real_capacity;
}

void
bfree(buffer_t *ptr)
{
    if (ptr == NULL)
        return;
    ptr->idx      = 0;
    ptr->len      = 0;
    ptr->capacity = 0;
    if (ptr->data != NULL) {
        ss_free(ptr->data);
    }
}

int
rand_bytes(void *output, int len)
{
    randombytes_buf(output, len);
    // always return success
    return 0;
}

crypto_t *
crypto_init(const char *password, const char *method)
{
    int i, m = -1;

    if (method != NULL) {
        for (i = 0; i < STREAM_CIPHER_NUM; i++) {
            if (strcmp(method, supported_stream_ciphers[i]) == 0) {
                m = i;
                break;
            }
        }
        if (m != -1) {
            cipher_t *cipher = stream_init(password, method);
            if (cipher == NULL) 
                return NULL;
            crypto_t *crypto = (crypto_t *)malloc(sizeof(crypto_t));
            crypto_t tmp = {
                .cipher = cipher,
                .encrypt_all = &stream_encrypt_all,
                .decrypt_all = &stream_decrypt_all,
                .encrypt = &stream_encrypt,
                .decrypt = &stream_decrypt,
                .ctx_init = &stream_ctx_init,
                .ctx_release = &stream_ctx_release
            };
            memcpy(crypto, &tmp, sizeof(crypto_t));
            return crypto;
        }

#if 0
        for (i = 0; i < AEAD_CIPHER_NUM; i++) {
            if (strcmp(method, aead_supported_ciphers[i]) == 0) {
                m = i;
                break;
            }
        }
        if (m != -1) {
            aead_init(password, method);
            crypto_t crypto = {
                .method = m,
                .encrypt_all = &aead_encrypt_all,
                .decrypt_all = &aead_decrypt_all,
                .encrypt = &aead_encrypt,
                .decrypt = &aead_decrypt,
                .ctx_init = &aead_ctx_init,
                .ctx_release = &aead_ctx_release
            };
            return m;
        }
#endif

    }

    LOGE("invalid cipher name: %s", method);
    return NULL;
}
