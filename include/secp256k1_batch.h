#ifndef SECP256K1_BATCH_H
#define SECP256K1_BATCH_H

#include "include/secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** This module implements a Batch Verification object that supports:
 *
 *  1. Schnorr signatures compliant with Bitcoin Improvement Proposal 340
 *     "Schnorr Signatures for secp256k1"
 *     (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
 *
 *  2. Taproot commitments compliant with Bitcoin Improvemtn Proposal 341
 *     "Taproot: SegWit version 1 spending rules"
 *     (https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki).
 */

/** Opaque data structure that holds information required for the batch verification.
 *
 *  The purpose of this structure is to store elliptic curve points, their scalars,
 *  and scalar of generator point participating in Multi-Scalar Point Multiplication
 *  computation. This computation is done by secp256k1_ecmult_strauss_batch or
 *  secp256k1_ecmult_pippenger_batch.
 */
typedef struct secp256k1_batch_struct secp256k1_batch;

/** Create a secp256k1 batch object object (in dynamically allocated memory).
 *
 *  This function uses malloc to allocate memory. It is guaranteed that malloc is
 *  called at most twice for every call of this function.
 *
 *  Returns: a newly created batch object.
 *  Args:        ctx:  an existing secp256k1_context object. Not to be confused
 *                     with the batch object object that this function creates.
 *  In:      max_terms:  max number of (scalar, curve point) pairs that the batch
 *                     object can store.
 */
SECP256K1_API secp256k1_batch* secp256k1_batch_create(
    const secp256k1_context* ctx,
    size_t max_terms
) SECP256K1_ARG_NONNULL(1) SECP256K1_WARN_UNUSED_RESULT;

/** Destroy a secp256k1 batch object (created in dynamically allocated memory).
 *
 *  The batch object's pointer may not be used afterwards.
 *
 *  Args:       ctx: a secp256k1 context object.
 *        batch: an existing batch object to destroy, constructed
 *                   using secp256k1_batch_create
 */
SECP256K1_API void secp256k1_batch_destroy(
    const secp256k1_context* ctx,
    secp256k1_batch* batch
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Verify the set of schnorr signatures or tweaked pubkeys present in the secp256k1_batch.
 *
 *  Returns: 1: correct schnorrsigs/tweaks
 *           0: incorrect schnorrsigs/tweaks
 *
 *  In particular, returns 1 if the batch object is empty (i.e, batch->len = 0).
 *
 *  Args:    ctx: a secp256k1 context object (can be initialized for none).
 *     batch: a secp256k1 batch object that contains a set of schnorrsigs/tweaks.
 */
SECP256K1_API int secp256k1_batch_verify(
    const secp256k1_context *ctx,
    secp256k1_batch *batch
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_BATCH_H */
