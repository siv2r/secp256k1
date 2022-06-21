#ifndef SECP256K1_MODULE_SCHNORRSIG_BATCH_ADD_IMPL_H
#define SECP256K1_MODULE_SCHNORRSIG_BATCH_ADD_IMPL_H

#include "include/secp256k1_schnorrsig.h"
#include "src/hash.h"
#include "src/modules/batch/main_impl.h"

static int secp256k1_batch_schnorrsig_randomizer(const secp256k1_context *ctx, secp256k1_batch *batch, secp256k1_scalar *r, const unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_xonly_pubkey *pubkey) {
    secp256k1_sha256 sha256_cpy;
    unsigned char randomizer[32];
    unsigned char buf[33];
    size_t buflen = sizeof(buf);
    int overflow;

    /* We use compressed serialization here. If we would use
    * xonly_pubkey serialization and a user would wrongly memcpy
    * normal secp256k1_pubkeys into xonly_pubkeys then the randomizer
    * would be the same for two different pubkeys. */
    if (!secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, (const secp256k1_pubkey *) pubkey, SECP256K1_EC_COMPRESSED)) {
        return 0;
    }

    /* add schnorrsig data to sha256 object */
    secp256k1_sha256_write(&batch->sha256, sig64, 64);
    secp256k1_sha256_write(&batch->sha256, msg, msglen);
    secp256k1_sha256_write(&batch->sha256, buf, buflen);

    /* generate randomizer */
    sha256_cpy = batch->sha256;
    secp256k1_sha256_finalize(&sha256_cpy, randomizer);
    secp256k1_scalar_set_b32(r, randomizer, &overflow);
    VERIFY_CHECK(overflow == 0);

    return 1;
}

/** Adds the given schnorrsig data to the batch object.
 *
 *  Updates the batch object by:
 *     1. adding the points R and P to the scratch space
 *     2. adding the scalars ai and ai.e to the scratch space
 *          -> ai   is the scalar coefficient of R (in multi multiplication)
 *          -> ai.e is the scalar coefficient of P (in multi multiplication)
 *     3. incrementing sc_g (scalar of G) by -ai.s
 *
 *  Conventions used above:
 *     -> R (nonce commitment) = EC point whose y = even and x = sig64[0:32]
 *     -> P (public key)       = pubkey
 *     -> ai (randomizer)      = sha256_tagged(sig64 || msg || pubkey)
 *     -> e (challenge)        = sha256_tagged(sig64[0:32] || pk.x || msg)
 *     -> s                    = sig64[32:64]
 *
 * This function's algorithm is based on secp256k1_schnorrsig_verify.
 */
int secp256k1_batch_add_schnorrsig(const secp256k1_context* ctx, secp256k1_batch *batch, const unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_xonly_pubkey *pubkey) {
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
    ARG_CHECK(batch != NULL);
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

    /* run verify if batch object's scratch is full */
    if (batch->capacity - batch->len < 2) {
        printf("\nbatch_add: Batch object is full...\n");
        printf("batch_add: Verifying the batch object...\n");
        if (!secp256k1_batch_verify(ctx, batch)) {
            /* tell user there is no point in adding sigs/tweaks?? */
            /* it will fail anyway */
        }
        printf("batch_add: Clearing the batch object for future use...\n");
        secp256k1_batch_scratch_clear(batch);
    }

    i = batch->len;
    /* append point R to the scratch space */
    if (!secp256k1_ge_set_xo_var(&r, &rx, 0)) {
        return 0;
    }
    if (!secp256k1_ge_is_in_correct_subgroup(&r)) {
        return 0;
    }
    secp256k1_gej_set_ge(&batch->points[i], &r);

    /* append point P to the scratch space */
    secp256k1_gej_set_ge(&batch->points[i+1], &pk);

    /* Compute e */
    secp256k1_fe_get_b32(buf, &pk.x);
    secp256k1_schnorrsig_challenge(&e, &sig64[0], msg, msglen, buf);

    /* Compute ai */
    if (!secp256k1_batch_schnorrsig_randomizer(ctx, batch, &ai, sig64, msg, msglen, pubkey)) {
        return 0;
    }

    /* append scalars ai, ai.e respectively to scratch space */
    batch->scalars[i] = ai;
    secp256k1_scalar_mul(&e, &e, &ai);
    batch->scalars[i+1] = e;

    /* increment scalar of G by -ai.s */
    secp256k1_scalar_mul(&s, &s, &ai);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_scalar_add(&batch->sc_g, &batch->sc_g, &s);

    batch->len += 2;

    return 1;
}

#endif /* SECP256K1_MODULE_SCHNORRSIG_BATCH_ADD_IMPL_H */
