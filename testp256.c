/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/spake/openssl.c - SPAKE implementations using OpenSSL */
/*
 * Copyright (C) 2015 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

struct state {
    EC_GROUP *group;
    BIGNUM *order;
    BN_CTX *ctx;
    EC_POINT *M;
    EC_POINT *N;
};

static uint8_t P256_M[] = {
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7,
    0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab,
    0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f
};

static uint8_t P256_N[] = {
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99,
    0x7f, 0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49,
    0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49
};

static struct state *
init()
{
    struct state *st;

    st = calloc(1, sizeof(*st));
    st->group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    st->ctx = BN_CTX_new();
    st->order = BN_new();
    EC_GROUP_get_order(st->group, st->order, st->ctx);
    st->M = EC_POINT_new(st->group);
    EC_POINT_oct2point(st->group, st->M, P256_M, sizeof(P256_M), st->ctx);
    st->N = EC_POINT_new(st->group);
    EC_POINT_oct2point(st->group, st->N, P256_N, sizeof(P256_N), st->ctx);
    return st;
}

static inline BIGNUM *
unmarshal_w(struct state *st, const uint8_t *wbytes)
{
    BIGNUM *w = NULL;

    w = BN_new();
    BN_set_flags(w, BN_FLG_CONSTTIME);
    BN_bin2bn(wbytes, 32, w) && BN_div(NULL, w, w, st->order, st->ctx);
    return w;
}

static void
keygen(struct state *st, const uint8_t *wbytes, int use_m, uint8_t *prv_out,
       uint8_t *pub_out)
{
    const EC_POINT *constant = use_m ? st->M : st->N;
    EC_POINT *pub = NULL;
    BIGNUM *prv = NULL;
    BIGNUM *w = NULL;

    w = unmarshal_w(st, wbytes);
    pub = EC_POINT_new(st->group);
    prv = BN_new();
    BN_rand_range(prv, st->order);

    /* Compute prv*G + w*constant; EC_POINT_mul() does this in one call. */
    EC_POINT_mul(st->group, pub, prv, constant, w, st->ctx);

    /* Marshal prv into prv_out. */
    memset(prv_out, 0, 32);
    BN_bn2bin(prv, &prv_out[32 - BN_num_bytes(prv)]);

    /* Marshal pub into pub_out. */
    EC_POINT_point2oct(st->group, pub, POINT_CONVERSION_COMPRESSED,
                       pub_out, 33, st->ctx);

    EC_POINT_free(pub);
    BN_clear_free(prv);
    BN_clear_free(w);
}

static void
result(struct state *st, const uint8_t *wbytes, const uint8_t *ourprv,
       const uint8_t *theirpub, int use_m, uint8_t *elem_out)
{
    const EC_POINT *constant = use_m ? st->M : st->N;
    EC_POINT *result = NULL;
    EC_POINT *pub = NULL;
    BIGNUM *priv = NULL;
    BIGNUM *w = NULL;

    w = unmarshal_w(st, wbytes);
    priv = BN_bin2bn(ourprv, 32, NULL);
    pub = EC_POINT_new(st->group);
    /* XXX verifies point, so make sure to pass a valid one */
    EC_POINT_oct2point(st->group, pub, theirpub, 33, st->ctx);

    /* Compute result = priv*(pub - w*constant), using result to hold the
     * intermediate steps. */
    result = EC_POINT_new(st->group);
    EC_POINT_mul(st->group, result, NULL, constant, w, st->ctx);
    EC_POINT_invert(st->group, result, st->ctx);
    EC_POINT_add(st->group, result, pub, result, st->ctx);
    EC_POINT_mul(st->group, result, NULL, result, priv, st->ctx);

    /* Marshal result into elem_out. */
    EC_POINT_point2oct(st->group, result, POINT_CONVERSION_COMPRESSED,
                       elem_out, 33, st->ctx);
    BN_clear_free(priv);
    BN_clear_free(w);
    EC_POINT_free(pub);
    EC_POINT_free(result);
}

int
main(int argc, char **argv)
{
    uint8_t w[32], prv1[32], prv2[32], pub1[33], pub2[33], key1[33], key2[33];
    struct state *st;
    int i, iter = atoi(argv[1]);

    st = init();
    memset(w, 0, sizeof(w));
    for (i = 0; i < iter; i++) {
	keygen(st, w, 1, prv1, pub1);
        keygen(st, w, 0, prv2, pub2);
        result(st, w, prv1, pub2, 0, key1);
        result(st, w, prv2, pub1, 1, key2);
    }
    return 0;
}
