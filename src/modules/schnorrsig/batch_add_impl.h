#ifndef SECP256K1_BATCH_ADD_IMPL_H
#define SECP256K1_BATCH_ADD_IMPL_H

#include "../../batch_impl.h"

/** Adds the given schnorrsig data to the batch context.
 * 
 *  appends (ai, R), (ai.e, P) to the batch context's scratch space
 *  R = nonce commitment - secp256k1_gej 
 *  X = pubkey - secp256k1_gej
 *  ai = randomizer - secp256k1_scalar
 * 
 *  increments the scalar of G (in the batch context) by -ai.s
 *  s = sig64[32:64]
 */
/*todo: run transparent verification, if batch is full */
int secp256k1_batch_context_add_schnorrsig(const secp256k1_context* ctx, secp256k1_batch_context *batch_ctx, const unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_xonly_pubkey *pubkey) {
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_scalar ai;
    secp256k1_ge pk;
    secp256k1_fe rx;
    secp256k1_ge r;
    unsigned char buf[32];
    int overflow;
    size_t i = 2*batch_ctx->len; /* todo: any MAX/2 check required? (like in prev impl) */

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

    /* Compute e. */
    secp256k1_fe_get_b32(buf, &pk.x);
    secp256k1_schnorrsig_challenge(&e, &sig64[0], msg, msglen, buf);
    
    /* Compute ai */
    secp256k1_scalar_set_int(&ai, 1);

    /* append scalars ai, ai.e respectively to scratch space */
    batch_ctx->scalars[i] = ai;
    secp256k1_scalar_mul(&e, &e, &ai);
    batch_ctx->scalars[i+1] = e;

    /* increment scalar of G by -ai.s */
    secp256k1_scalar_mul(&s, &s, &ai);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_scalar_add(&batch_ctx->sc_g, &batch_ctx->sc_g, &s);
    
    batch_ctx->len += 1;
    
    return 1;
}

#endif