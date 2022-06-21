#ifndef SECP256K1_MODULE_EXTRAKEYS_BATCH_ADD_IMPL_H
#define SECP256K1_MODULE_EXTRAKEYS_BATCH_ADD_IMPL_H

#include "include/secp256k1_extrakeys.h"
#include "src/hash.h"
#include "src/modules/batch/main_impl.h"

static int secp256k1_batch_xonlypub_tweak_check_randomizer(const secp256k1_context* ctx, secp256k1_batch *batch, secp256k1_scalar *r, const unsigned char *tweaked_pubkey32, int tweaked_pk_parity, const secp256k1_xonly_pubkey *internal_pubkey,const unsigned char *tweak32) {
    secp256k1_sha256 sha256_cpy;
    unsigned char randomizer[32];
    unsigned char parity = (unsigned char) tweaked_pk_parity;
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

    /* add tweaked pubkey check data to sha object */
    secp256k1_sha256_write(&batch->sha256, tweaked_pubkey32, 32);
    secp256k1_sha256_write(&batch->sha256, &parity, sizeof(parity));
    secp256k1_sha256_write(&batch->sha256, tweak32, 32);
    secp256k1_sha256_write(&batch->sha256, internal_buf, internal_buflen);

    /* generate randomizer */
    sha256_cpy = batch->sha256;
    secp256k1_sha256_finalize(&sha256_cpy, randomizer);
    secp256k1_scalar_set_b32(r, randomizer, &overflow);
    VERIFY_CHECK(overflow == 0);

    return 1;
}

/** Adds the given tweaked pubkey check data to the batch object.
 *
 *  Updates the batch object by:
 *     1. adding the points Q and P to the scratch space
 *          -> the points are of type secp256k1_gej
 *     2. adding the scalars -ai and ai to the scratch space
 *          -> -ai is the scalar coefficient of Q (in multi multiplication)
 *          ->  ai is the scalar coefficient of P (in multi multiplication)
 *     3. incrementing sc_g (scalar of G) by -ai.tweak
 *
 *  Conventions used above:
 *     -> Q (tweaked pubkey)   = EC point where parity(y) = tweaked_pk_parity
 *                               and x = tweaked_pubkey32
 *     -> P (internal pubkey)  = internal pubkey
 *     -> ai (randomizer)      = sha256_tagged(tweaked_pubkey32  ||
 *                                             tweaked_pk_parity || tweak32 || pubkey)
 *     -> tweak (challenge)    = tweak32
 *
 * This function's algorithm is based on secp256k1_xonly_pubkey_tweak_add_check.
 */
int secp256k1_batch_add_xonlypub_tweak_check(const secp256k1_context* ctx, secp256k1_batch *batch, const unsigned char *tweaked_pubkey32, int tweaked_pk_parity, const secp256k1_xonly_pubkey *internal_pubkey,const unsigned char *tweak32) {
    secp256k1_scalar tweak;
    secp256k1_scalar ai;
    secp256k1_scalar tmp;
    secp256k1_ge pk;
    secp256k1_ge q;
    secp256k1_fe qx;
    int overflow;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(batch != NULL);
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

    /* run verify if batch object's scratch is full */
    /* todo: create a function to do this?? */
    if (batch->capacity - batch->len < 2) {
        printf("\nbatch_add_xonlypub_tweak: Batch object is full...\n");
        printf("batch_add_xonlypub_tweak: Verifying the batch object...\n");
        if (!secp256k1_batch_verify(ctx, batch)) {
            /* tell user there is no point in adding sigs/tweaks?? */
            /* it will fail anyway */
        }
        printf("batch_add_xonlypub_tweak: Clearing the batch object for future use...\n");
        secp256k1_batch_scratch_clear(batch);
    }

    i = batch->len;
    /* append point Q to the scratch space */
    if (!secp256k1_ge_set_xo_var(&q, &qx, tweaked_pk_parity)) {
        return 0;
    }
    if (!secp256k1_ge_is_in_correct_subgroup(&q)) {
        return 0;
    }
    secp256k1_gej_set_ge(&batch->points[i], &q);

    /* append point P to the scratch space */
    secp256k1_gej_set_ge(&batch->points[i+1], &pk);

    /* Compute ai */
    if (!secp256k1_batch_xonlypub_tweak_check_randomizer(ctx, batch, &ai, tweaked_pubkey32, tweaked_pk_parity, internal_pubkey, tweak32)) {
        return 0;
    }

    /* append scalars -ai, ai respectively to scratch space */
    secp256k1_scalar_negate(&tmp, &ai);
    batch->scalars[i] = tmp;
    batch->scalars[i+1] = ai;

    /* increment scalar of G by ai.tweak */
    secp256k1_scalar_mul(&tweak, &tweak, &ai);
    secp256k1_scalar_add(&batch->sc_g, &batch->sc_g, &tweak);

    batch->len += 2;

    return 1;
}

#endif /* SECP256K1_MODULE_EXTRAKEYS_BATCH_ADD_IMPL_H */
