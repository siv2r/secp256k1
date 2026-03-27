#ifndef SECP256K1_MODULE_BATCH_MAIN_H
#define SECP256K1_MODULE_BATCH_MAIN_H

#include "../../../include/secp256k1_batch.h"

/* Ensures unique randomizers across different batch_add_* functions.
 *
 * Without this tag, two batch contexts could generate identical randomizers
 * if given the same input bytes, even when using different batch_add_*
 * functions (e.g., batch_add_tweak_check vs batch_add_schnorrsig).
 *
 * Including this tag in randomizer generation prevents such collisions by
 * differentiating between the different batch_add_* function types.
 */
enum batch_add_type {schnorrsig = 1, tweak_check = 2};

/** Opaque data structure for batch verification context.
 *
 *  Members:
 *    scalars: pointer to dynamically allocated scalars array.
 *     points: pointer to dynamically allocated points (secp256k1_ge) array.
 *       sc_g: scalar corresponding to the generator point (G) in the
 *             multi-scalar multiplication equation.
 *     sha256: hash of all inputs (signatures/tweaks) in the batch except the first.
 *             Used to generate a random secp256k1_scalar for each term added by
 *             secp256k1_batch_add_*.
 *        len: number of scalar-point pairs currently in the batch.
 *   capacity: maximum number of scalar-point pairs the batch can hold.
 *  mem_limit: the memory budget (in bytes) for the multi-scalar multiplication
 *             algorithm's internal working memory.
 *     result: indicates whether all inputs (signatures or tweak checks) are valid.
 *             1 = valid, 0 = invalid. Initialized to 1 by secp256k1_batch_create.
 *
 *  This struct is typedef'd as secp256k1_batch in include/secp256k1_batch.h.
 */
struct secp256k1_batch_struct{
    secp256k1_scalar *scalars;
    secp256k1_ge *points;
    secp256k1_scalar sc_g;
    secp256k1_sha256 sha256;
    size_t len;
    size_t capacity;
    size_t mem_limit;
    int result;
};

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/batch")||SHA256("BIP0340/batch"). */
static void secp256k1_batch_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x79e3e0d2ul;
    sha->s[1] = 0x12284f32ul;
    sha->s[2] = 0xd7d89e1cul;
    sha->s[3] = 0x6491ea9aul;
    sha->s[4] = 0xad823b2ful;
    sha->s[5] = 0xfacfe0b6ul;
    sha->s[6] = 0x342b78baul;
    sha->s[7] = 0x12ece87cul;

    sha->bytes = 64;
}

secp256k1_batch* secp256k1_batch_create(const secp256k1_context* ctx, size_t mem_limit, const unsigned char *aux_rand16) {
    const secp256k1_hash_ctx *hash_ctx;
    secp256k1_batch* batch;
    size_t capacity;
    unsigned char zeros[16] = {0};

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(mem_limit != 0);

    hash_ctx = secp256k1_get_hash_context(ctx);
    capacity = secp256k1_ecmult_multi_batch_size(mem_limit);
    if (capacity == 0) {
        return NULL;
    }

    batch = (secp256k1_batch *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_batch));
    if (batch == NULL) {
        return NULL;
    }

    batch->scalars = (secp256k1_scalar *)checked_malloc(&ctx->error_callback, capacity * sizeof(secp256k1_scalar));
    batch->points = (secp256k1_ge *)checked_malloc(&ctx->error_callback, capacity * sizeof(secp256k1_ge));
    if (batch->scalars == NULL || batch->points == NULL) {
        free(batch->scalars);
        free(batch->points);
        free(batch);
        return NULL;
    }

    batch->capacity = capacity;
    batch->mem_limit = mem_limit;
    secp256k1_scalar_set_int(&batch->sc_g, 0);
    secp256k1_batch_sha256_tagged(&batch->sha256);
    if (aux_rand16 != NULL) {
        secp256k1_sha256_write(hash_ctx, &batch->sha256, aux_rand16, 16);
    } else {
        secp256k1_sha256_write(hash_ctx, &batch->sha256, zeros, 16);
    }
    batch->len = 0;
    batch->result = 1;

    return batch;
}

void secp256k1_batch_reset(const secp256k1_context *ctx, secp256k1_batch *batch) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK_VOID(batch != NULL);

    batch->len = 0;
    secp256k1_scalar_set_int(&batch->sc_g, 0);
    secp256k1_batch_sha256_tagged(&batch->sha256);
    batch->result = 1;
}

void secp256k1_batch_destroy(const secp256k1_context *ctx, secp256k1_batch *batch) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK_VOID(batch != NULL);

    if (batch != NULL) {
        free(batch->scalars);
        free(batch->points);
        free(batch);
    }
}

int secp256k1_batch_verify(const secp256k1_context *ctx, secp256k1_batch *batch) {
    secp256k1_gej resj;
    int ecmult_ret;
    int mid_res;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(batch != NULL);
    ARG_CHECK(batch->len <= batch->capacity);

    if(batch->result == 0) {
        return 0;
    }

    if (batch->len > 0) {
        ecmult_ret = secp256k1_ecmult_multi(&ctx->error_callback, &resj, batch->len, batch->points, batch->scalars, &batch->sc_g, batch->mem_limit);
        mid_res = secp256k1_gej_is_infinity(&resj);

        VERIFY_CHECK(ecmult_ret != 0);
        (void)ecmult_ret;

        batch->result = batch->result && mid_res;
        batch->len = 0;
        secp256k1_scalar_set_int(&batch->sc_g, 0);
    }

    return batch->result;
}

#endif /* SECP256K1_MODULE_BATCH_MAIN_H */
