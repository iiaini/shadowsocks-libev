/*
 * encrypt.c - Manage AEAD ciphers
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

#include <mbedtls/version.h>
#define CIPHER_UNSUPPORTED "unsupported"
#include <time.h>
#include <stdio.h>

#include <sodium.h>
#include <arpa/inet.h>

#include "cache.h"
#include "aead.h"
#include "utils.h"

#define NONE                    (-1)
#define AES128GCM               0
#define AES192GCM               1
#define AES256GCM               2
/*
 * methods above requires gcm context
 * methods below doesn't require it,
 * then we need to fake one
 */
#define CHACHA20POLY1305        3
#define CHACHA20POLY1305IETF    4

#ifdef FS_HAVE_XCHACHA20IETF
#define XCHACHA20POLY1305IETF   5
#endif

#define CHUNK_SIZE_LEN          2

/*
 * This is SIP004 proposed by @Mygod, the design of TCP chunk is from @breakwa11 and
 * @Noisyfox. This first version of this file is written by @wongsyrone.
 *
 * The first nonce is either from client or server side, it is generated via randombytes_buf()
 * in libsodium, and the sequent nonces are incremented via sodium_increment() in libsodium.
 *
 * Data.Len is used to separate general ciphertext and Auth tag. We can start decryption
 * if and only if the verification is passed.
 * Firstly, we do length check, then decrypt it, separate ciphertext and attached data tag
 * based on the verified length, verify data tag and decrypt the corresponding data.
 * Finally, do what you supposed to do, e.g. forward user data.
 *
 * For UDP, nonces are generated randomly without the incrementation.
 *
 * TCP request (before encryption)
 * +------+---------------------+------------------+
 * | ATYP | Destination Address | Destination Port |
 * +------+---------------------+------------------+
 * |  1   |       Variable      |         2        |
 * +------+---------------------+------------------+
 *
 * TCP request (after encryption, *ciphertext*)
 * +--------+--------------+------------------+--------------+---------------+
 * | NONCE  |  *HeaderLen* |   HeaderLen_TAG  |   *Header*   |  Header_TAG   |
 * +--------+--------------+------------------+--------------+---------------+
 * | Fixed  |       2      |       Fixed      |   Variable   |     Fixed     |
 * +--------+--------------+------------------+--------------+---------------+
 *
 * Header input: atyp + dst.addr + dst.port
 * HeaderLen is length(atyp + dst.addr + dst.port)
 * Header_TAG and Header_TAG are in plaintext
 *
 * TCP Chunk (before encryption)
 * +----------+
 * |  DATA    |
 * +----------+
 * | Variable |
 * +----------+
 *
 * Data.Len is a 16-bit big-endian integer indicating the length of DATA.
 *
 * TCP Chunk (after encryption, *ciphertext*)
 * +--------------+---------------+--------------+------------+
 * |  *DataLen*   |  DataLen_TAG  |    *Data*    |  Data_TAG  |
 * +--------------+---------------+--------------+------------+
 * |      2       |     Fixed     |   Variable   |   Fixed    |
 * +--------------+---------------+--------------+------------+
 *
 * Len_TAG and DATA_TAG have the same length, they are in plaintext.
 * After encryption, DATA -> DATA*
 *
 * UDP (before encryption)
 * +------+---------------------+------------------+----------+
 * | ATYP | Destination Address | Destination Port |   DATA   |
 * +------+---------------------+------------------+----------+
 * |  1   |       Variable      |         2        | Variable |
 * +------+---------------------+------------------+----------+
 *
 * UDP (after encryption, *ciphertext*)
 * +--------+-----------+-----------+
 * | NONCE  |  *Data*   |  Data_TAG |
 * +--------+-----------+-----------+
 * | Fixed  | Variable  |   Fixed   |
 * +--------+-----------+-----------+
 *
 * *Data* is Encrypt(atyp + dst.addr + dst.port + payload)
 * RSV and FRAG are dropped
 * Since UDP packet is either received completely or missed,
 * we don't have to keep a field to track its length.
 *
 */

#ifdef DEBUG
static void
dump(char *tag, char *text, int len)
{
    int i;
    printf("%s: ", tag);
    for (i = 0; i < len; i++)
        printf("0x%02x ", (uint8_t)text[i]);
    printf("\n");
}

#endif

const char *supported_aead_ciphers[CIPHER_NUM] = {
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
#ifdef FS_HAVE_XCHACHA20IETF
    "xchacha20-ietf-poly1305"
#endif
};

/*
 * use mbed TLS cipher wrapper to unify handling
 */
static const char *supported_aead_ciphers_mbedtls[CIPHER_NUM] = {
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
#ifdef FS_HAVE_XCHACHA20IETF
    CIPHER_UNSUPPORTED
#endif
};

static const int supported_aead_ciphers_nonce_size[CIPHER_NUM] = {
    12, 12, 12, 8, 12,
#ifdef FS_HAVE_XCHACHA20IETF
    24
#endif
};

static const int supported_aead_ciphers_key_size[CIPHER_NUM] = {
    16, 24, 32, 32, 32,
#ifdef FS_HAVE_XCHACHA20IETF
    32
#endif
};

static const int supported_aead_ciphers_tag_size[CIPHER_NUM] = {
    16, 16, 16, 16, 16,
#ifdef FS_HAVE_XCHACHA20IETF
    16
#endif
};

static int
cipher_nonce_size(const cipher_t *cipher)
{
    if (cipher == NULL) {
        return 0;
    }
    return cipher->info->iv_size;
}

/*
 * return key size form cipher info structure
 * return our fake one for those don't need
 * cipher context
 */
int
cipher_key_size(const cipher_t *cipher)
{
    if (cipher == NULL) {
        return 0;
    }
    return cipher->info->key_bitlen / 8;
}

int
derive_key(const cipher_t *cipher,
           const uint8_t *pass,
           uint8_t *key)
{
    if (pass == NULL) {
        LOGE("derive_key(): password is empty");
        return 0;
    }
    int key_size    = cipher_key_size(cipher);
    size_t pass_len = strlen((const char *)pass);
    int ret         = crypto_generichash(key, key_size,
                                         pass, pass_len,
                                         NULL, 0);
    if (ret != 0) {
        LOGE("derive_key(): failed to generic hash");
        return 0;
    }
    return key_size;
}

static int
cipher_aead_encrypt(cipher_ctx_t *cipher_ctx,
                    uint8_t *c,
                    size_t *clen,
                    uint8_t *m,
                    size_t mlen,
                    uint8_t *ad,
                    size_t *adlen,
                    uint8_t *n,
                    size_t nlen,
                    size_t tlen,
                    uint8_t *k)
{
    int err            = CRYPTO_ERROR;
    uint64_t long_clen = -1;

    switch (method) {
    case AES128GCM:
    case AES192GCM:
    case AES256GCM:
        err = mbedtls_cipher_auth_encrypt(cipher_ctx->evp, n, nlen, ad, adlen,
                                          m, mlen, c, clen, c + nlen + mlen, tlen);
        long_clen += tlen;
        break;
    case CHACHA20POLY1305:
        err = crypto_aead_chacha20poly1305_encrypt(c, &long_clen, m, mlen,
                                                   ad, adlen, NULL, n, k);
        break;
    case CHACHA20POLY1305IETF:
        err = crypto_aead_chacha20poly1305_ietf_encrypt(c, &long_clen, m, mlen,
                                                        ad, adlen, NULL, n, k);
        break;
#ifdef FS_HAVE_XCHACHA20IETF
    case XCHACHA20POLY1305IETF:
        err = crypto_aead_xchacha20poly1305_ietf_encrypr(c, &long_clen, m, mlen,
                                                         ad, adlen, NULL, n, k);
        break;
#endif
    default:
        return CRYPTO_ERROR;
    }

    *clen = (size_t)long_clen; // it's safe to cast 64bit to 32bit length here

    return err;
}

static int
cipher_aead_decrypt(cipher_ctx_t *cipher_ctx,
                    uint8_t *p,
                    size_t *plen,
                    uint8_t *m,
                    size_t mlen,
                    uint8_t *ad,
                    size_t *adlen,
                    uint8_t *n,
                    size_t nlen,
                    size_t tlen,
                    uint8_t *k)
{
    int err            = CRYPTO_ERROR;
    uint64_t long_plen = -1;

    switch (cipher_ctx->cipher->method) {
    case AES128GCM:
    case AES192GCM:
    case AES256GCM:
        err = mbedtls_cipher_auth_decrypt(cipher_ctx->evp, n, nlen, ad, adlen,
                                          m, mlen, p, plen, m + nlen + mlen, tlen);
        break;
    case CHACHA20POLY1305:
        err = crypto_aead_chacha20poly1305_decrypt(p, &long_plen, NULL, m, mlen,
                                                   ad, adlen, n, k);
        break;
    case CHACHA20POLY1305IETF:
        err = crypto_aead_chacha20poly1305_ietf_decrypt(p, &long_plen, NULL, m, mlen,
                                                        ad, adlen, n, k);
        break;
#ifdef FS_HAVE_XCHACHA20IETF
    case XCHACHA20POLY1305IETF:
        err = crypto_aead_xchacha20poly1305_ietf_decrypr(p, &long_plen, NULL, m, mlen,
                                                         ad, adlen, n, k);
        break;
#endif
    default:
        return CRYPTO_ERROR;
    }

    if (long_plen != -1) {
        *plen = (size_t)long_plen; // it's safe to cast 64bit to 32bit length here
    }

    return err;
}

/*
 * get basic cipher info structure
 * it's a wrapper offered by crypto library
 */
const cipher_kt_t *
get_cipher_type(int method)
{
    if (method < AES128GCM || method >= CIPHER_NUM) {
        LOGE("get_cipher_type(): Illegal method");
        return NULL;
    }

    /* cipher that don't use mbed TLS, just return */
    if (method >= CHACHA20POLY1305) {
        return NULL;
    }

    const char *ciphername  = supported_ciphers[method];
    const char *mbedtlsname = supported_ciphers_mbedtls[method];
    if (strcmp(mbedtlsname, CIPHER_UNSUPPORTED) == 0) {
        LOGE("Cipher %s currently is not supported by mbed TLS library",
             ciphername);
        return NULL;
    }
    return mbedtls_cipher_info_from_string(mbedtlsname);
}

static void
aead_cipher_ctx_init(cipher_ctx_t *ctx, int method, int enc)
{
    if (method < AES128GCM || method >= CIPHER_NUM) {
        LOGE("cipher_context_init(): Illegal method");
        return;
    }

    if (method >= CHACHA20POLY1305) {
        enc_nonce_len = supported_ciphers_nonce_size[method];
        return;
    }

    const char *ciphername = supported_ciphers[method];

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
    if (mbedtls_cipher_setkey(evp, enc_key, enc_key_len * 8, enc) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot set mbed TLS cipher key");
    }
    if (mbedtls_cipher_reset(evp) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot finish preparation of mbed TLS cipher context");
    }

#ifdef DEBUG
    dump("KEY", (char *)enc_key, enc_key_len);
#endif
}

void
aead_ctx_init(cipher_t *cipher, cipher_ctx_t *cipher_ctx, int enc)
{
    sodium_memzero(cipher_ctx, sizeof(cipher_ctx_t));
    aead_cipher_ctx_init(cipher_ctx, cipher->method, enc);
    cipher_ctx->cipher = cipher;

    if (enc) {
        rand_bytes(cipher_ctx->nonce, cipher->nonce_len);
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

/* UDP */
int
aead_encrypt_all(buffer_t *plaintext, cipher_t *cipher, size_t capacity)
{
    cipher_ctx_t cipher_ctx;
    aead_ctx_init(cipher, &cipher_ctx, 1);

    size_t nonce_len = cipher->nonce_len;
    size_t tag_len   = cipher->tag_len;
    int err          = 1;

    static buffer_t tmp = { 0, 0, 0, NULL };
    brealloc(&tmp, nonce_len + tag_len + plain->len, capacity);
    buffer_t *ciphertext = &tmp;
    ciphertext->len = tag_len + plain->len;

    // generate nonce
    uint8_t nonce[MAX_NONCE_LENGTH];
    rand_bytes(nonce, nonce_len);

    /* copy nonce to first pos */
    memcpy(cipher->data, nonce, nonce_len);

    size_t clen = ciphertext->len;
    err = cipher_aead_encrypt(cipher_ctx,
                              ciphertext->data + nonce_len,
                              &clen,
                              plaintext->data,
                              plaintext->len,
                              NULL,
                              0,
                              nonce,
                              cipher->key,
                              nonce_len,
                              tag_len);

    if (!err) {
        bfree(plaintext);
        cipher_ctx_release(&cipher_ctx);
        return CRYPTO_ERROR;
    }

#ifdef DEBUG
    dump("PLAIN", plain->data, plain->len);
    dump("CIPHER", cipher->data + nonce_len, cipher->len);
#endif

    cipher_ctx_release(&cipher_ctx);

    assert(ciphertext->len == clen);

    brealloc(plaintext, nonce_len + ciphertext->len, capacity);
    memcpy(plaintext->data, ciphertext->data, nonce_len + cipher->len);
    plaintext->len = nonce_len + cipher->len;

    return CRYPTO_OK;
}

int
aead_decrypt_all(cipher_t *cipher, buffer_t *ciphertext, size_t capacity)
{
    size_t nonce_len = cipher->nonce_len;
    size_t tag_len   = cipher->tag_len;
    int ret          = 1;

    if (ciphertext->len <= nonce_len + tag_len) {
        return CRYPTO_ERROR;
    }

    cipher_ctx_t cipher_ctx;
    cipher_ctx_init(cipher, &cipher_ctx, 0);

    static buffer_t tmp = { 0, 0, 0, NULL };
    brealloc(&tmp, ciphertext->len, capacity);
    buffer_t *plaintext = &tmp;
    plaintext->len = ciphertext->len - nonce_len - tag_len;

    /* get nonce */
    uint8_t nonce[MAX_NONCE_LENGTH];
    memcpy(nonce, ciphertext->data, nonce_len);

    size_t plen = plaintext->len;
    err = cipher_aead_decrypt(cipher_ctx,
                              plaintext->data,
                              &plen,
                              plaintext->data,
                              plaintext->len,
                              NULL,
                              0,
                              nonce,
                              cipher->key,
                              nonce_len,
                              tag_len);

    if (!ret) {
        bfree(ciphertext);
        cipher_ctx_release(&cipher_ctx);
        return -1;
    }

#ifdef DEBUG
    dump("PLAIN", plaintext->data, plaintext->len);
    dump("CIPHER", ciphertext->data + nonce_len, ciphertext->len - nonce_len);
#endif

    cipher_ctx_release(&cipher_ctx);

    brealloc(ciphertext, plaintext->len, capacity);
    memcpy(ciphertext->data, plaintext->data, plaintext->len);
    ciphertext->len = plaintext->len;

    return 0;
}

static int
aead_chunk_encrypt(cipher_ctx_t *ctx, uint8_t *p, uint8_t *c, uint8_t *n,
                   size_t plen, size_t nlen, size_t tlen)
{
    int err;
    size_t clen;
    char len_buf[2];
    memcpy(len_buf, ntohs(plen), CHUNK_SIZE_LEN);

    clen = CHUNK_SIZE_LEN + tlen;
    err = cipher_aead_encrypt(ctx, c, &clen, len_buf, CHUNK_SIZE_LEN,
            NULL, 0, n, ctx->cipher->key, nlen, tlen);
    if (err) return err;
    assert(clen == CHUNK_SIZE_LEN + tlen);

    clen = plen + tlen;
    err = cipher_aead_encrypt(ctx, c + CHUNK_SIZE_LEN + tlen, &clen, p, plen,
            NULL, 0, n, ctx->cipher->key, nlen, tlen);
    if (err) return err;
    assert(clen == plen + tlen);

    return CRYPTO_OK;
}

/* TCP */
int
aead_encrypt(buffer_t *plaintext, cipher_ctx *cipher_ctx, size_t capacity)
{
    static buffer_t tmp = { 0, 0, 0, NULL };
    buffer_t *ciphertext;

    cipher_t *cipher = cipher_ctx->cipher;
    int err          = CRYPTO_ERROR;
    size_t nonce_len = 0;
    size_t tag_len   = cipher->tag_len;

    if (!cipher_ctx->init) {
        nonce_len = cipher->nonce_len;
    }

    size_t out_len = nonce_len + 2 * tag_len + plaintext->len + CHUNK_SIZE_LEN;
    brealloc(&tmp, out_len, capacity);
    ciphertext = &tmp;
    ciphertext->len = out_len;

    if (!cipher_ctx->init) {
        memcpy(ciphertext->data, cipher_ctx->nonce, nonce_len);
        cipher_ctx->init = 1;
    }

    int err = aead_chunk_encrypt(cipher_ctx, plaintext->data, ciphertext->data + nonce_len,
            cipher_ctx->nonce, plaintext->len, nonce_len, tag_len);
    if (err) {
        return CRYPTO_ERROR;
    }

#ifdef DEBUG
    dump("PLAIN", plaintext->data, plaintext->len);
    dump("CIPHER", ciphertext->data + nonce_len, ciphertext->len);
#endif

    brealloc(plaintext, ciphertext->len, capacity);
    memcpy(plaintext->data, ciphertext->data, ciphertext->len);
    plaintext->len = ciphertext->len;

    return 0;
}

static int
aead_chunk_decrypt(cipher_ctx_t *ctx, uint8_t *p, uint8_t *c, uint8_t *n,
                   size_t clen, size_t nlen, size_t tlen)
{
    int err;
    size_t plen;
    size_t mlen;

    if (clen <= 2 * tlen + CHUNK_SIZE_LEN)
        return CRYPTO_NEED_MORE;

    char len_buf[2];
    memcpy(len_buf, ntohs(plen), CHUNK_SIZE_LEN);

    clen = CHUNK_SIZE_LEN + tlen;
    err = cipher_aead_encrypt(ctx, c, &clen, len_buf, CHUNK_SIZE_LEN,
            NULL, 0, n, ctx->cipher->key, nlen, tlen);
    if (err) return err;
    assert(clen == CHUNK_SIZE_LEN + tlen);

    clen = plen + tlen;
    err = cipher_aead_encrypt(ctx, c + CHUNK_SIZE_LEN + tlen, &clen, p, plen,
            NULL, 0, n, ctx->cipher->key, nlen, tlen);
    if (err) return err;
    assert(clen == plen + tlen);

    return CRYPTO_OK;
}

int
ss_decrypt(buffer_t *ciphertext, enc_ctx_t *ctx, size_t capacity)
{
    static buffer_t tmp = { 0, 0, 0, NULL };

    size_t nonce_len = enc_nonce_len;
    // size_t tag_len   = enc_tag_len;
    int err = 1;

    brealloc(&tmp, ciphertext->len, capacity);
    buffer_t *plaintext = &tmp;
    plaintext->len = ciphertext->len;

    // get nonce
    uint8_t nonce[MAX_NONCE_LENGTH];
    plaintext->len -= nonce_len;
    memcpy(nonce, ciphertext->data, nonce_len);
    // ciphertext_context_set_iv(&ctx->evp, iv, iv_len, 0);

    if (cache_key_exist(nonce_cache, (char *)nonce, nonce_len)) {
        bfree(ciphertext);
        return -1;
    } else {
        cache_insert(nonce_cache, (char *)nonce, nonce_len, NULL);
    }

    if (enc_method >= CHACHA20POLY1305) {
        // do what we want directly
    } else {
//         err = ciphertext_context_update(&ctx->evp, (uint8_t *)plaintext->data, &plaintext->len,
//                                     (const uint8_t *)(ciphertext->data + nonce_len),
//                                     ciphertext->len - nonce_len);
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

cipher_t *
aead_key_init(int method, const char *pass)
{
    if (method < AES128GCM || method >= CIPHER_NUM) {
        LOGE("enc_key_init(): Illegal method");
        return;
    }

    // Initialize cache
    cache_create(&nonce_cache, 1024, NULL);

    cipher_t *cipher = (cipher_t *)ss_malloc(sizeof(cipher_t));
    memset(cipher, 0, sizeof(cipher_t));

    // Initialize sodium for random generator
    if (sodium_init() == -1) {
        FATAL("Failed to initialize sodium");
    }

    if (method >= CHACHA20POLY1305) {
        cipher_kt_t *cipher_info = (cipher_kt_t *)ss_malloc(sizeof(cipher_kt_t));
        cipher->info             = &cipher_info;
        cipher->info->base       = NULL;
        cipher->info->key_bitlen = supported_aead_ciphers_key_size[method] * 8;
        cipher->info->iv_size    = supported_aead_ciphers_nonce_size[method];
    } else {
        cipher->info = (cipher_kt_t *)get_cipher_type(method);
    }

    if (cipher->info == NULL && cipher->key_len == 0) {
        LOGE("Cipher %s not found in crypto library", supported_ciphers[method]);
        FATAL("Cannot initialize cipher");
    }

    cipher->key_len = derive_key(&cipher, (const uint8_t *)pass, enc_key);

    if (cipher->key_len == 0) {
        FATAL("Cannot generate key and nonce");
    }

    cipher->nonce_len = cipher_nonce_size(&cipher);
    cipher->tag_len   = supported_ciphers_tag_size[method];
    cipher->method    = method;
}

cipher_t *
aead_init(const char *pass, const char *method)
{
    int m = AES128GCM;
    if (method != NULL) {
        /* check method validity */
        for (m = AES128GCM; m < CIPHER_NUM; m++)
            if (strcmp(method, supported_ciphers[m]) == 0) {
                break;
            }
        if (m >= CIPHER_NUM) {
            LOGE("Invalid cipher name: %s, use aes-256-gcm instead", method);
            m = AES256GCM;
        }
    }
    return aead_key_init(m, pass);
}
