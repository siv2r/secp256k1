#ifndef SECP256K1_BATCH_ADD_IMPL_H
#define SECP256K1_BATCH_ADD_IMPL_H

#include "../../../include/secp256k1_schnorrsig.h"
#include "../../hash.h"
#include "../../batch_impl.h"

int secp256k1_batch_schnorrsig_init_randomizer(const secp256k1_context *ctx, secp256k1_batch_context *batch_ctx, secp256k1_scalar *r, const unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_xonly_pubkey *pubkey) {
    secp256k1_sha256 sha256_cpy;
    unsigned char res[32];
    unsigned char buf[33];
    size_t buflen = sizeof(buf);
    int overflow;

    /* add schnorrsig data to sha256 object */
    secp256k1_sha256_write(&batch_ctx->sha256, sig64, 64);
    secp256k1_sha256_write(&batch_ctx->sha256, msg, msglen);
    /* We use compressed serialization here. If we would use
    * xonly_pubkey serialization and a user would wrongly memcpy
    * normal secp256k1_pubkeys into xonly_pubkeys then the randomizer
    * would be the same for two different pubkeys. */
    if (!secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, (const secp256k1_pubkey *) pubkey, SECP256K1_EC_COMPRESSED)) {
        return 0;
    }
    secp256k1_sha256_write(&batch_ctx->sha256, buf, buflen);

    /* generate randomizer */
    sha256_cpy = batch_ctx->sha256;
    secp256k1_sha256_finalize(&sha256_cpy, res);
    secp256k1_scalar_set_b32(r, res, &overflow);
    VERIFY_CHECK(overflow == 0); /*todo: is this check necessary? */

    return 1;
}


int secp256k1_batch_xonlypub_tweak_init_randomizer(const secp256k1_context* ctx, secp256k1_batch_context *batch_ctx, secp256k1_scalar *r, const unsigned char *tweaked_pubkey32, int tweaked_pk_parity, const secp256k1_xonly_pubkey *internal_pubkey,const unsigned char *tweak32) {
    secp256k1_sha256 sha256_cpy;
    unsigned char res[32];
    unsigned char tweaked_buf[33];
    unsigned char internal_buf[33];
    size_t internal_buflen = sizeof(internal_buf);
    int overflow;

    /* We use compressed serialization here. If we would use
    * xonly_pubkey serialization and a user would wrongly memcpy
    * normal secp256k1_pubkeys into xonly_pubkeys then the randomizer
    * would be the same for two different pubkeys. */
    if (!secp256k1_ec_pubkey_serialize(ctx, internal_buf, &internal_buflen, (const secp256k1_pubkey *) internal_pubkey, SECP256K1_EC_COMPRESSED)) {
        return 0;
    }
    tweaked_buf[0] = (tweaked_pk_parity == 0) ? 0x02 : 0x03;
    memcpy(tweaked_buf+1, tweaked_pubkey32, 32);

    /* add tweaked pubkey check data to sha object */
    secp256k1_sha256_write(&batch_ctx->sha256, tweaked_buf, sizeof(tweaked_buf));
    secp256k1_sha256_write(&batch_ctx->sha256, tweak32, 32);
    secp256k1_sha256_write(&batch_ctx->sha256, internal_buf, internal_buflen);

    /* generate randomizer */
    sha256_cpy = batch_ctx->sha256;
    secp256k1_sha256_finalize(&sha256_cpy, res);
    secp256k1_scalar_set_b32(r, res, &overflow);
    VERIFY_CHECK(overflow == 0); /*todo: is this check necessary? */

    return 1;
}


/** Adds the given schnorrsig data to the batch context.
 *  This function's algorithm is based on secp256k1_schnorrsig_verify.
 *
 *  appends (ai, R), (ai.e, P) to the batch context's scratch space
 *  R = nonce commitment - secp256k1_gej
 *  P = pubkey - secp256k1_gej
 *  ai = randomizer - secp256k1_scalar
 *
 *  increments the scalar of G (in the batch context) by -ai.s, where
 *  s = sig64[32:64]
 */
/*todo: run transparent verification, if batch is full */
/* todo: any MAX/2 check required? (like in prev impl) */
int secp256k1_batch_context_add_schnorrsig(const secp256k1_context* ctx, secp256k1_batch_context *batch_ctx, const unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_xonly_pubkey *pubkey) {
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_scalar ai;
    secp256k1_ge pk;
    secp256k1_fe rx;
    secp256k1_ge r;
    unsigned char buf[32];
    int overflow;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg != NULL || msglen == 0);
    ARG_CHECK(pubkey != NULL);

    if (!secp256k1_fe_set_b32(&rx, &sig64[0])) {
        return 0;
    }

    secp256k1_scalar_set_b32(&s, &sig64[32], &overflow);
    if (overflow) {
        return 0;
    }

    if (!secp256k1_xonly_pubkey_load(ctx, &pk, pubkey)) {
        return 0;
    }

    /* run verify if batch context's scratch is full */
    if (batch_ctx->capacity - batch_ctx->len < 2) {
        printf("\nbatch_add: Batch context is full...\n");
        printf("batch_add: Verifying the batch context...\n");
        if (!secp256k1_batch_verify(&ctx->error_callback, batch_ctx)) {
            /* tell user there is no point in adding sigs/tweaks?? */
            /* it will fail anyway */
        }
        printf("batch_add: Clearing the batch context for future use...\n");
        secp256k1_batch_scratch_clear(&ctx->error_callback, batch_ctx);
        if (!secp256k1_batch_scratch_alloc(&ctx->error_callback, batch_ctx)) {
            return 0;
        }
    }

    i = batch_ctx->len;
    /* append point R to the scratch space */
    if (!secp256k1_ge_set_xo_var(&r, &rx, 0)) {/* todo: is rx > prime order, checked here? */
        return 0;
    }
    if (!secp256k1_ge_is_in_correct_subgroup(&r)) {
        return 0;
    }
    /* secp256k1_fe_normalize(&r.y); */
    secp256k1_gej_set_ge(&batch_ctx->points[i], &r);

    /* append point P to the scratch space */
    secp256k1_gej_set_ge(&batch_ctx->points[i+1], &pk);

    /* Compute e */
    secp256k1_fe_get_b32(buf, &pk.x);
    secp256k1_schnorrsig_challenge(&e, &sig64[0], msg, msglen, buf);

    /* Compute ai */
    if (!secp256k1_batch_schnorrsig_init_randomizer(ctx, batch_ctx, &ai, sig64, msg, msglen, pubkey)) {
        return 0;
    }

    /* append scalars ai, ai.e respectively to scratch space */
    batch_ctx->scalars[i] = ai;
    secp256k1_scalar_mul(&e, &e, &ai);
    batch_ctx->scalars[i+1] = e;

    /* increment scalar of G by -ai.s */
    secp256k1_scalar_mul(&s, &s, &ai);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_scalar_add(&batch_ctx->sc_g, &batch_ctx->sc_g, &s);

    batch_ctx->len += 2;

    return 1;
}

/** Adds the given xonly pubkey tweak check data to the batch context.
 *  This function's algorithm is based on secp256k1_xonly_pubkey_tweak_add_check.
 *
 *  appends (-ai, Q), (ai, P) to the batch context's scratch space
 *  Q = tweaked pubkey - secp256k1_gej
 *  P = internal pubkey - secp256k1_gej
 *  ai = randomizer - secp256k1_scalar
 *
 *  increments the scalar of G (in the batch context) by ai.tweak times
 */
/*todo: run transparent verification, if batch is full */
/* todo: any MAX/2 check required? (like in prev impl) */
int secp256k1_batch_context_add_xonlypub_tweak(const secp256k1_context* ctx, secp256k1_batch_context *batch_ctx, const unsigned char *tweaked_pubkey32, int tweaked_pk_parity, const secp256k1_xonly_pubkey *internal_pubkey,const unsigned char *tweak32) {
    secp256k1_scalar tweak;
    secp256k1_scalar ai;
    secp256k1_scalar tmp;
    secp256k1_ge pk;
    secp256k1_ge q;
    secp256k1_fe qx;
    int overflow;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(internal_pubkey != NULL);
    ARG_CHECK(tweaked_pubkey32 != NULL);
    ARG_CHECK(tweak32 != NULL);

    if (!secp256k1_fe_set_b32(&qx, tweaked_pubkey32)) {
        return 0;
    }

    secp256k1_scalar_set_b32(&tweak, tweak32, &overflow);
    if (overflow) {
        return 0;
    }

    if (!secp256k1_xonly_pubkey_load(ctx, &pk, internal_pubkey)) {
        return 0;
    }

    /* run verify if batch context's scratch is full */
    /* todo: create a function to do this?? */
    if (batch_ctx->capacity - batch_ctx->len < 2) {
        printf("\nbatch_add_xonlypub_tweak: Batch context is full...\n");
        printf("batch_add_xonlypub_tweak: Verifying the batch context...\n");
        if (!secp256k1_batch_verify(&ctx->error_callback, batch_ctx)) {
            /* tell user there is no point in adding sigs/tweaks?? */
            /* it will fail anyway */
        }
        printf("batch_add_xonlypub_tweak: Clearing the batch context for future use...\n");
        secp256k1_batch_scratch_clear(&ctx->error_callback, batch_ctx);
        if (!secp256k1_batch_scratch_alloc(&ctx->error_callback, batch_ctx)) {
            return 0;
        }
    }

    i = batch_ctx->len;
    /* append point Q to the scratch space */
    if (!secp256k1_ge_set_xo_var(&q, &qx, tweaked_pk_parity)) {
        return 0;
    }
    if (!secp256k1_ge_is_in_correct_subgroup(&q)) {
        return 0;
    }
    secp256k1_gej_set_ge(&batch_ctx->points[i], &q);

    /* append point P to the scratch space */
    secp256k1_gej_set_ge(&batch_ctx->points[i+1], &pk);

    /* Compute ai */
    if(!secp256k1_batch_xonlypub_tweak_init_randomizer(ctx, batch_ctx, &ai, tweaked_pubkey32, tweaked_pk_parity, internal_pubkey, tweak32)) {
        return 0;
    }

    /* append scalars -ai, ai respectively to scratch space */
    secp256k1_scalar_negate(&tmp, &ai);
    batch_ctx->scalars[i] = tmp;
    batch_ctx->scalars[i+1] = ai;

    /* increment scalar of G by ai.tweak */
    secp256k1_scalar_mul(&tweak, &tweak, &ai);
    secp256k1_scalar_add(&batch_ctx->sc_g, &batch_ctx->sc_g, &tweak);

    batch_ctx->len += 2;

    return 1;
}

#endif