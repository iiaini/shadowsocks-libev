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

#ifndef _AEAD_H
#define _AEAD_H

#include "crypto.h"


// currently, XCHACHA20POLY1305IETF is not released yet
// XCHACHA20POLY1305 is removed in upstream
#ifdef FS_HAVE_XCHACHA20IETF
#define AEAD_CIPHER_NUM              6
#else
#define AEAD_CIPHER_NUM              5
#endif

/* for udprelay */
int aead_encrypt_all(buffer_t *plaintext, int method, size_t capacity);
int aead_decrypt_all(buffer_t *ciphertext, int method, size_t capacity);

/* for local, redir, manager, etc */
int aead_encrypt(buffer_t *plaintext, enc_ctx_t *ctx, size_t capacity);
int aead_decrypt(buffer_t *ciphertext, enc_ctx_t *ctx, size_t capacity);

void aead_ctx_init(int method, enc_ctx_t *ctx, int enc);
void aead_ctx_release(cipher_ctx_t *evp);
int aead_init(const char *pass, const char *method);

#endif // _AEAD_H
