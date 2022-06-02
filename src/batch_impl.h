#ifndef SECP256K1_BATCH_IMPL_H
#define SECP256K1_BATCH_IMPL_H

#include "../include/secp256k1.h"
#include "util.h"

/** Opaque data structure that holds context information for schnorr batch verification.
 *
 *  Members:
 *       data: scratch space object that contains points (gej) and their 
 *             respective scalars. To be used in Multi-Scalar Multiplication
 *             algorithms such as Strauss and Pippenger.
 *    scalars: pointer to scalars allocated on the scratch space.
 *     points: pointer to points allocated on the scratch space.
 *       sc_g: scalar corresponding to the generator point in Multi-Scalar
 *             Multiplication equation.
 *        len: number of inputs (schnorrsigs/tweaks) that user entered.
 *     rounds: number of times batch context's scratch space was cleared by batch_add_*,
 *             which happens when the user adds more inputs than the capacity.
 *             than the capacity. 
 *   capacity: max number of inputs (schnorrsigs/tweaks) that the batch object
 *             can hold
 *     result: tells whether the given set of inputs (schnorrsigs/tweaks) is valid
 *             or invalid. 1 = valid and 0 = invalid.
 * 
 *  The following struct name is typdef as secp256k1_batch_context (in include/secp256k1.h). 
 */

struct secp256k1_batch_context_struct{
    secp256k1_scratch *data;
    secp256k1_scalar *scalars;
    secp256k1_gej *points;
    secp256k1_scalar sc_g;
    size_t len;
    size_t rounds;
    size_t capacity;
    int result;
};

size_t secp256k1_batch_scratch_size(int n_terms) {
    size_t ret = secp256k1_strauss_scratch_size(n_terms) + STRAUSS_SCRATCH_OBJECTS*16;
    /* Return value of 0 is reserved for error */
    VERIFY_CHECK(ret != 0);

    return ret;
}

secp256k1_batch_context* secp256k1_batch_create(const secp256k1_callback* error_callback, size_t n_terms) {
    size_t batch_size = sizeof(secp256k1_batch_context);
    size_t batch_scratch_size = secp256k1_batch_scratch_size(2*n_terms);
    size_t checkpoint;
    secp256k1_batch_context* batch_ctx = (secp256k1_batch_context*)checked_malloc(&default_error_callback, batch_size);

    VERIFY_CHECK(batch_size != 0);

    if (batch_ctx != NULL) {
        /* create scratch space inside batch context */
        batch_ctx->data = secp256k1_scratch_create(error_callback, batch_scratch_size);
        checkpoint = secp256k1_scratch_checkpoint(error_callback, batch_ctx->data);

        /* allocate 2*n_terms scalars and points on scratch space */
        batch_ctx->scalars = (secp256k1_scalar*)secp256k1_scratch_alloc(error_callback, batch_ctx->data, 2*n_terms*sizeof(secp256k1_scalar));
        batch_ctx->points = (secp256k1_gej*)secp256k1_scratch_alloc(error_callback, batch_ctx->data, 2*n_terms*sizeof(secp256k1_gej));
        /* if scalar or point allocation fails, free all the previous the allocated memory
           and return NULL */
        if (batch_ctx->scalars == NULL || batch_ctx->points == NULL) {
            secp256k1_scratch_apply_checkpoint(error_callback, batch_ctx->data, checkpoint);
            secp256k1_scratch_destroy(error_callback, batch_ctx->data);
            free(batch_ctx);
            return NULL;
        }
        
        /* set remaining data members */
        secp256k1_scalar_clear(&batch_ctx->sc_g);
        batch_ctx->len = 0;
        batch_ctx->rounds = 0;
        batch_ctx->capacity = n_terms;
        batch_ctx->result = 0;
    }

    return batch_ctx;
}

void secp256k1_batch_destroy(const secp256k1_callback* error_callback, secp256k1_batch_context* batch_ctx) {
    if (batch_ctx != NULL) {
        if(batch_ctx->data != NULL) {
            secp256k1_scratch_apply_checkpoint(error_callback, batch_ctx->data, 0);
            secp256k1_scratch_destroy(error_callback, batch_ctx->data);
        }
        free(batch_ctx);
    }
}

/** Batch verifies the schnorrsig/tweaks present in the batch context object.
 *  If the batch context is empty, 
 * 
 * calls secp256k1_ecmult_strauss_batch on a scratch space filled with 2n points
 * and 2n scalars, where n = no of terms (user input in secp256k1_batch_context_create)
 * 
 * Fails if:
 * 0 != -(s1 + a2*s2 + ... + au*su)G
 *      + R1 + a2*R2 + ... + au*Ru + e1*P1 + (a2*e2)P2 + ... + (au*eu)Pu.
 */
int secp256k1_batch_verify(const secp256k1_callback* error_callback, secp256k1_batch_context* batch_ctx) {
    secp256k1_gej resj;
    int mid_res;

    if (batch_ctx->len > 0) {
        if(batch_ctx->scalars != NULL && batch_ctx->points != NULL) {
            mid_res = secp256k1_ecmult_strauss_batch(error_callback, batch_ctx->data, &resj,  batch_ctx->scalars, batch_ctx->points, &batch_ctx->sc_g, NULL, NULL, batch_ctx->len, 0) && secp256k1_gej_is_infinity(&resj);

            if (batch_ctx->rounds > 0){
                batch_ctx->result = batch_ctx->result && mid_res;
            } else {
                batch_ctx->result = mid_res;
            }
        }
    }

    return batch_ctx->result;
}

#endif