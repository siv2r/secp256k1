#ifndef SECP256K1_BATCH_ADD_IMPL_H
#define SECP256K1_BATCH_ADD_IMPL_H

#include "../../batch_impl.h"

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