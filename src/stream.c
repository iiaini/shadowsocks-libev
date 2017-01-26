/*
 * stream.c - Manage stream ciphers.
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
 * You should have recenonceed a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <mbedtls/md5.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/version.h>
#define CIPHER_UNSUPPORTED "unsupported"

#include <sodium.h>

#include "cache.h"
#include "stream.h"
#include "utils.h"

#define OFFSET_ROL(p, o) ((uint64_t)(*(p + o)) << (8 * o))

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


static struct cache *nonce_cache;

const char *supported_stream_ciphers[STREAM_CIPHER_NUM] = {
    "table",
    "rc4",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "cast5-cfb",
    "des-cfb",
    "idea-cfb",
    "rc2-cfb",
    "seed-cfb",
    "salsa20",
    "chacha20",
#if SODIUM_LIBRARY_VERSION_MAJOR >= 8
    "chacha20-ietf"
#endif
};

static const char *supported_stream_ciphers_mbedtls[STREAM_CIPHER_NUM] = {
    "table",
    "ARC4-128",
    "ARC4-128",
    "AES-128-CFB128",
    "AES-192-CFB128",
    "AES-256-CFB128",
    "AES-128-CTR",
    "AES-192-CTR",
    "AES-256-CTR",
    "BLOWFISH-CFB64",
    "CAMELLIA-128-CFB128",
    "CAMELLIA-192-CFB128",
    "CAMELLIA-256-CFB128",
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    "salsa20",
    "chacha20",
#if SODIUM_LIBRARY_VERSION_MAJOR >= 8
    "chacha20-ietf"
#endif
};

static const int supported_stream_ciphers_nonce_size[STREAM_CIPHER_NUM] = {
    0, 0, 16, 16, 16, 16, 16, 16, 16, 8, 16, 16, 16, 8, 8, 8, 8, 16, 8, 8
#if SODIUM_LIBRARY_VERSION_MAJOR >= 8
    , 12
#endif
};

static const int supported_stream_ciphers_key_size[STREAM_CIPHER_NUM] = {
    0, 16, 16, 16, 24, 32, 16, 24, 32, 16, 16, 24, 32, 16, 8, 16, 16, 16, 32, 32
#if SODIUM_LIBRARY_VERSION_MAJOR >= 8
    , 32
#endif
};

static int
crypto_stream_xor_ic(uint8_t *c, const uint8_t *m, uint64_t mlen,
                     const uint8_t *n, uint64_t ic, const uint8_t *k,
                     int method)
{
    switch (method) {
    case SALSA20:
        return crypto_stream_salsa20_xor_ic(c, m, mlen, n, ic, k);
    case CHACHA20:
        return crypto_stream_chacha20_xor_ic(c, m, mlen, n, ic, k);
#if SODIUM_LIBRARY_VERSION_MAJOR >= 8
    case CHACHA20IETF:
        return crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, n, (uint32_t)ic, k);
#endif
    }
    // always return 0
    return 0;
}

static unsigned char *
ss_md5(const unsigned char *d, size_t n, unsigned char *md)
{
    static unsigned char m[16];
    if (md == NULL) {
        md = m;
    }
    mbedtls_md5(d, n, md);
    return md;
}

#ifdef DEBUG
void
dump(char *tag, char *text, int len)
{
    int i;
    printf("%s: ", tag);
    for (i = 0; i < len; i++)
        printf("0x%02x ", (uint8_t)text[i]);
    printf("\n");
}
#endif

int
cipher_nonce_size(const cipher_t *cipher)
{
    if (cipher == NULL) {
        return 0;
    }
    return cipher->info->iv_size;
}

int
cipher_key_size(const cipher_t *cipher)
{
    /*
     * Semi-API changes (technically public, morally prnonceate)
     * Renamed a few headers to include _internal in the name. Those headers are
     * not supposed to be included by users.
     * Changed md_info_t into an opaque structure (use md_get_xxx() accessors).
     * Changed pk_info_t into an opaque structure.
     * Changed cipher_base_t into an opaque structure.
     */
    if (cipher == NULL) {
        return 0;
    }
    /* From Version 1.2.7 released 2013-04-13 Default Blowfish keysize is now 128-bits */
    return cipher->info->key_bitlen / 8;
}

int
bytes_to_key(const cipher_t *cipher, const digest_type_t *md,
             const uint8_t *pass, uint8_t *key)
{
    size_t datal;
    datal = strlen((const char *)pass);

    mbedtls_md_context_t c;
    unsigned char md_buf[MAX_MD_SIZE];
    int nkey;
    int addmd;
    unsigned int i, j, mds;

    nkey = cipher_key_size(cipher);
    mds  = mbedtls_md_get_size(md);
    memset(&c, 0, sizeof(mbedtls_md_context_t));

    if (pass == NULL)
        return nkey;
    if (mbedtls_md_setup(&c, md, 1))
        return 0;

    for (j = 0, addmd = 0; j < nkey; addmd++) {
        mbedtls_md_starts(&c);
        if (addmd) {
            mbedtls_md_update(&c, md_buf, mds);
        }
        mbedtls_md_update(&c, pass, datal);
        mbedtls_md_finish(&c, &(md_buf[0]));

        for (i = 0; i < mds; i++, j++) {
            if (j >= nkey)
                break;
            key[j] = md_buf[i];
        }
    }

    mbedtls_md_free(&c);
    return nkey;
}

const cipher_kt_t *
get_cipher_type(int method)
{
    if (method <= TABLE || method >= STREAM_CIPHER_NUM) {
        LOGE("get_cipher_type(): Illegal method");
        return NULL;
    }

    if (method == RC4_MD5) {
        method = RC4;
    }

    if (method >= SALSA20) {
        return NULL;
    }

    const char *ciphername = supported_stream_ciphers[method];
    const char *mbedtlsname = supported_stream_ciphers_mbedtls[method];
    if (strcmp(mbedtlsname, CIPHER_UNSUPPORTED) == 0) {
        LOGE("Cipher %s currently is not supported by mbed TLS library",
             ciphername);
        return NULL;
    }
    return mbedtls_cipher_info_from_string(mbedtlsname);
}

const digest_type_t *
get_digest_type(const char *digest)
{
    if (digest == NULL) {
        LOGE("get_digest_type(): Digest name is null");
        return NULL;
    }

    return mbedtls_md_info_from_string(digest);
}

void
stream_cipher_ctx_init(cipher_ctx_t *ctx, int method, int enc)
{
    if (method <= TABLE || method >= STREAM_CIPHER_NUM) {
        LOGE("stream_ctx_init(): Illegal method");
        return;
    }

    if (method >= SALSA20) {
        return;
    }

    const char *ciphername = supported_stream_ciphers[method];
    const cipher_kt_t *cipher = get_cipher_type(method);

    ctx->evp = ss_malloc(sizeof(cipher_evp_t));
    memset(ctx->evp, 0, sizeof(cipher_evp_t));
    cipher_evp_t *evp = ctx->evp;

    if (cipher == NULL) {
        LOGE("Cipher %s not found in mbed TLS library", ciphername);
        FATAL("Cannot initialize mbed TLS cipher");
    }
    mbedtls_cipher_init(evp);
    if (mbedtls_cipher_setup(evp, cipher) != 0) {
        FATAL("Cannot initialize mbed TLS cipher context");
    }
}

void
stream_cipher_ctx_release(cipher_ctx_t *cipher_ctx)
{
    mbedtls_cipher_free(cipher_ctx->evp);
    ss_free(cipher_ctx->evp);
}

void
cipher_ctx_set_nonce(cipher_ctx_t *cipher_ctx, uint8_t *nonce, size_t nonce_len,
                      int enc)
{
    const unsigned char *true_key;

    cipher_t *cipher = cipher_ctx->cipher;

    if (nonce == NULL) {
        LOGE("cipher_ctx_set_nonce(): NONCE is null");
        return;
    }

    if (!enc) {
        memcpy(cipher_ctx->nonce, nonce, cipher->nonce_len);
    }

    if (cipher->method >= SALSA20) {
        return;
    }

    if (cipher->method == RC4_MD5) {
        unsigned char key_nonce[32];
        memcpy(key_nonce, cipher->key, 16);
        memcpy(key_nonce + 16, cipher_ctx->nonce, 16);
        true_key = ss_md5(key_nonce, 32, NULL);
        nonce_len   = 0;
    } else {
        true_key = cipher->key;
    }

    cipher_evp_t *evp = cipher_ctx->evp;
    if (evp == NULL) {
        LOGE("cipher_ctx_set_nonce(): Cipher context is null");
        return;
    }
    if (mbedtls_cipher_setkey(evp, true_key, cipher->key_len * 8, enc) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot set mbed TLS cipher key");
    }

    if (mbedtls_cipher_set_iv(evp, nonce, nonce_len) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot set mbed TLS cipher NONCE");
    }
    if (mbedtls_cipher_reset(evp) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot finalize mbed TLS cipher context");
    }

#ifdef DEBUG
    dump("NONCE", (char *)nonce, nonce_len);
#endif
}

static int
cipher_ctx_update(cipher_ctx_t *ctx, uint8_t *output, size_t *olen,
                      const uint8_t *input, size_t ilen)
{
    cipher_evp_t *evp = ctx->evp;
    return !mbedtls_cipher_update(evp, (const uint8_t *)input, ilen,
                                  (uint8_t *)output, olen);
}

int
stream_encrypt_all(buffer_t *plaintext, cipher_t *cipher, size_t capacity)
{
    cipher_ctx_t cipher_ctx;
    stream_ctx_init(cipher, &cipher_ctx, 1);

    size_t nonce_len = cipher->nonce_len;
    int err       = 1;

    static buffer_t tmp = { 0, 0, 0, NULL };
    brealloc(&tmp, nonce_len + plaintext->len, capacity);
    buffer_t *ciphertext = &tmp;
    ciphertext->len = plaintext->len;

    uint8_t nonce[MAX_NONCE_LENGTH];

    rand_bytes(nonce, nonce_len);
    cipher_ctx_set_nonce(&cipher_ctx, nonce, nonce_len, 1);
    memcpy(ciphertext->data, nonce, nonce_len);

    if (cipher->method >= SALSA20) {
        crypto_stream_xor_ic((uint8_t *)(ciphertext->data + nonce_len),
                (const uint8_t *)plaintext->data, (uint64_t)(plaintext->len),
                (const uint8_t *)nonce,
                0, cipher->key, cipher->method);
    } else {
        err = cipher_ctx_update(&cipher_ctx, (uint8_t *)(ciphertext->data + nonce_len),
                &ciphertext->len, (const uint8_t *)plaintext->data,
                plaintext->len);
    }

    if (!err) {
        bfree(plaintext);
        stream_ctx_release(&cipher_ctx);
        return -1;
    }

#ifdef DEBUG
    dump("PLAIN", plaintext->data, plaintext->len);
    dump("CIPHER", ciphertext->data + nonce_len, ciphertext->len);
#endif

    stream_ctx_release(&cipher_ctx);

    brealloc(plaintext, nonce_len + ciphertext->len, capacity);
    memcpy(plaintext->data, ciphertext->data, nonce_len + ciphertext->len);
    plaintext->len = nonce_len + ciphertext->len;

    return 0;
}

int
stream_encrypt(buffer_t *plaintext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
    if (cipher_ctx == NULL)
        return -1;

    cipher_t *cipher = cipher_ctx->cipher;
    
    static buffer_t tmp = { 0, 0, 0, NULL };

    int err       = 1;
    size_t nonce_len = 0;
    if (!cipher_ctx->init) {
        nonce_len = cipher_ctx->cipher->nonce_len;
    }

    brealloc(&tmp, nonce_len + plaintext->len, capacity);
    buffer_t *ciphertext = &tmp;
    ciphertext->len = plaintext->len;

    if (!cipher_ctx->init) {
        cipher_ctx_set_nonce(cipher_ctx, cipher_ctx->nonce, nonce_len, 1);
        memcpy(ciphertext->data, cipher_ctx->nonce, nonce_len);
        cipher_ctx->counter = 0;
        cipher_ctx->init    = 1;
    }

    if (cipher->method >= SALSA20) {
        int padding = cipher_ctx->counter % SODIUM_BLOCK_SIZE;
        brealloc(ciphertext, nonce_len + (padding + ciphertext->len) * 2, capacity);
        if (padding) {
            brealloc(plaintext, plaintext->len + padding, capacity);
            memmove(plaintext->data + padding, plaintext->data, plaintext->len);
            sodium_memzero(plaintext->data, padding);
        }
        crypto_stream_xor_ic((uint8_t *)(ciphertext->data + nonce_len),
                (const uint8_t *)plaintext->data,
                (uint64_t)(plaintext->len + padding),
                (const uint8_t *)cipher_ctx->nonce,
                cipher_ctx->counter / SODIUM_BLOCK_SIZE, cipher->key,
                cipher->method);
        cipher_ctx->counter += plaintext->len;
        if (padding) {
            memmove(ciphertext->data + nonce_len,
                    ciphertext->data + nonce_len + padding, ciphertext->len);
        }
    } else {
        err =
            cipher_ctx_update(cipher_ctx,
                    (uint8_t *)(ciphertext->data + nonce_len),
                    &ciphertext->len, (const uint8_t *)plaintext->data,
                    plaintext->len);
        if (!err) {
            return -1;
        }
    }

#ifdef DEBUG
    dump("PLAIN", plaintext->data, plaintext->len);
    dump("CIPHER", ciphertext->data + nonce_len, ciphertext->len);
#endif

    brealloc(plaintext, nonce_len + ciphertext->len, capacity);
    memcpy(plaintext->data, ciphertext->data, nonce_len + ciphertext->len);
    plaintext->len = nonce_len + ciphertext->len;

    return 0;
}

int
stream_decrypt_all(buffer_t *ciphertext, cipher_t *cipher, size_t capacity)
{
    size_t nonce_len = cipher->nonce_len;
    int ret       = 1;

    if (ciphertext->len <= nonce_len) {
        return -1;
    }

    cipher_ctx_t cipher_ctx;
    stream_ctx_init(cipher, &cipher_ctx, 0);

    static buffer_t tmp = { 0, 0, 0, NULL };
    brealloc(&tmp, ciphertext->len, capacity);
    buffer_t *plaintext = &tmp;
    plaintext->len = ciphertext->len - nonce_len;

    uint8_t nonce[MAX_NONCE_LENGTH];
    memcpy(nonce, ciphertext->data, nonce_len);
    cipher_ctx_set_nonce(&cipher_ctx, nonce, nonce_len, 0);

    if (cipher->method >= SALSA20) {
        crypto_stream_xor_ic((uint8_t *)plaintext->data,
                (const uint8_t *)(ciphertext->data + nonce_len),
                (uint64_t)(ciphertext->len - nonce_len),
                (const uint8_t *)nonce, 0, cipher->key, cipher->method);
    } else {
        ret = cipher_ctx_update(&cipher_ctx, (uint8_t *)plaintext->data, &plaintext->len,
                (const uint8_t *)(ciphertext->data + nonce_len),
                ciphertext->len - nonce_len);
    }

    if (!ret) {
        bfree(ciphertext);
        stream_ctx_release(&cipher_ctx);
        return -1;
    }

#ifdef DEBUG
    dump("PLAIN", plaintext->data, plaintext->len);
    dump("CIPHER", ciphertext->data + nonce_len, ciphertext->len - nonce_len);
#endif

    stream_ctx_release(&cipher_ctx);

    brealloc(ciphertext, plaintext->len, capacity);
    memcpy(ciphertext->data, plaintext->data, plaintext->len);
    ciphertext->len = plaintext->len;

    return 0;
}

int
stream_decrypt(buffer_t *ciphertext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
    if (cipher_ctx == NULL) return -1;

    cipher_t *cipher = cipher_ctx->cipher;

    static buffer_t tmp = { 0, 0, 0, NULL };

    size_t nonce_len = 0;
    int err       = 1;

    brealloc(&tmp, ciphertext->len, capacity);
    buffer_t *plaintext = &tmp;
    plaintext->len = ciphertext->len;

    if (!cipher_ctx->init) {
        uint8_t nonce[MAX_NONCE_LENGTH];
        nonce_len      = cipher->nonce_len;
        plaintext->len -= nonce_len;

        memcpy(nonce, ciphertext->data, nonce_len);
        cipher_ctx_set_nonce(cipher_ctx, nonce, nonce_len, 0);
        cipher_ctx->counter = 0;
        cipher_ctx->init    = 1;

        if (cipher->method >= RC4_MD5) {
            if (cache_key_exist(nonce_cache, (char *)nonce, nonce_len)) {
                bfree(ciphertext);
                return -1;
            } else {
                cache_insert(nonce_cache, (char *)nonce, nonce_len, NULL);
            }
        }
    }

    if (cipher->method >= SALSA20) {
        int padding = cipher_ctx->counter % SODIUM_BLOCK_SIZE;
        brealloc(plaintext, (plaintext->len + padding) * 2, capacity);

        if (padding) {
            brealloc(ciphertext, ciphertext->len + padding, capacity);
            memmove(ciphertext->data + nonce_len + padding, ciphertext->data + nonce_len,
                    ciphertext->len - nonce_len);
            sodium_memzero(ciphertext->data + nonce_len, padding);
        }
        crypto_stream_xor_ic((uint8_t *)plaintext->data,
                (const uint8_t *)(ciphertext->data + nonce_len),
                (uint64_t)(ciphertext->len - nonce_len + padding),
                (const uint8_t *)cipher_ctx->nonce,
                cipher_ctx->counter / SODIUM_BLOCK_SIZE, cipher->key,
                cipher->method);
        cipher_ctx->counter += ciphertext->len - nonce_len;
        if (padding) {
            memmove(plaintext->data, plaintext->data + padding, plaintext->len);
        }
    } else {
        err = cipher_ctx_update(cipher_ctx, (uint8_t *)plaintext->data, &plaintext->len,
                (const uint8_t *)(ciphertext->data + nonce_len),
                ciphertext->len - nonce_len);
    }

    if (!err) {
        bfree(ciphertext);
        return -1;
    }

#ifdef DEBUG
    dump("PLAIN", plaintext->data, plaintext->len);
    dump("CIPHER", ciphertext->data + nonce_len, ciphertext->len - nonce_len);
#endif

    brealloc(ciphertext, plaintext->len, capacity);
    memcpy(ciphertext->data, plaintext->data, plaintext->len);
    ciphertext->len = plaintext->len;

    return 0;
}

void
stream_ctx_init(cipher_t *cipher, cipher_ctx_t *cipher_ctx, int enc)
{
    sodium_memzero(cipher_ctx, sizeof(cipher_ctx_t));
    stream_cipher_ctx_init(cipher_ctx, cipher->method, enc);
    cipher_ctx->cipher = cipher;

    if (enc) {
        rand_bytes(cipher_ctx->evp->iv, cipher->nonce_len);
    }
}

void
stream_ctx_release(cipher_ctx_t *cipher_ctx)
{
    if (cipher_ctx->cipher->method >= SALSA20) {
        return;
    }

    mbedtls_cipher_free(cipher_ctx->evp);
    ss_free(cipher_ctx->evp);
}

cipher_t *
stream_key_init(int method, const char *pass)
{
    if (method <= TABLE || method >= STREAM_CIPHER_NUM) {
        LOGE("cipher->key_init(): Illegal method");
        return NULL;
    }

    // Initialize cache
    cache_create(&nonce_cache, 1024, NULL);

    cipher_t *cipher = (cipher_t *)malloc(sizeof(cipher_t));
    memset(cipher, 0, sizeof(cipher_t));

    // Initialize sodium for random generator
    if (sodium_init() == -1) {
        FATAL("Failed to initialize sodium");
    }

    if (method == SALSA20 || method == CHACHA20 || method == CHACHA20IETF) {
        cipher_kt_t *cipher_info = (cipher_kt_t *)malloc(sizeof(cipher_kt_t));
        cipher->info             = cipher_info;
        cipher->info->base       = NULL;
        cipher->info->key_bitlen = supported_stream_ciphers_key_size[method] * 8;
        cipher->info->iv_size    = supported_stream_ciphers_nonce_size[method];
    } else {
        cipher->info = (cipher_kt_t *)get_cipher_type(method);
    }

    if (cipher->info == NULL && cipher->key_len == 0) {
        LOGE("Cipher %s not found in crypto library", supported_stream_ciphers[method]);
        FATAL("Cannot initialize cipher");
    }

    const digest_type_t *md = get_digest_type("MD5");
    if (md == NULL) {
        FATAL("MD5 Digest not found in crypto library");
    }

    cipher->key_len = bytes_to_key(cipher, md, (const uint8_t *)pass, cipher->key);

    if (cipher->key_len == 0) {
        FATAL("Cannot generate key and NONCE");
    }
    if (method == RC4_MD5) {
        cipher->nonce_len = 16;
    } else {
        cipher->nonce_len = cipher_nonce_size(cipher);
    }
    cipher->method = method;

    return cipher;
}

cipher_t *
stream_init(const char *pass, const char *method)
{
    int m = TABLE;
    if (method != NULL) {
        for (m = TABLE; m < STREAM_CIPHER_NUM; m++)
            if (strcmp(method, supported_stream_ciphers[m]) == 0) {
                break;
            }
        if (m >= STREAM_CIPHER_NUM) {
            LOGE("Invalid cipher name: %s, use rc4-md5 instead", method);
            m = RC4_MD5;
        }
    }
    if (m == TABLE) {
        LOGE("Table is deprecated");
        return NULL;
    }
    return stream_key_init(m, pass);
}

