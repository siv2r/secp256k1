#ifndef SECP256K1_MODULE_BATCH_TESTS_H
#define SECP256K1_MODULE_BATCH_TESTS_H

#include "include/secp256k1_batch.h"

#define MAX_TERMS 10


/* Tests for the equality of two sha256 structs. This function only produces a
 * correct result if an integer multiple of 64 many bytes have been written
 * into the hash functions. */
void batch_test_sha256_eq(const secp256k1_sha256 *sha1, const secp256k1_sha256 *sha2) {
    /* Is buffer fully consumed? */
    CHECK((sha1->bytes & 0x3F) == 0);

    CHECK(sha1->bytes == sha2->bytes);
    CHECK(secp256k1_memcmp_var(sha1->s, sha2->s, sizeof(sha1->s)) == 0);
}

/* Checks that hash initialized by secp256k1_batch_sha256_tagged has the
 * expected state. */
void test_batch_sha256_tagged(void) {
    unsigned char tag[13] = "BIP0340/batch";
    secp256k1_sha256 sha;
    secp256k1_sha256 sha_optimized;

    secp256k1_sha256_initialize_tagged(&sha, (unsigned char *) tag, sizeof(tag));
    secp256k1_batch_sha256_tagged(&sha_optimized);
    batch_test_sha256_eq(&sha, &sha_optimized);
}

void test_batch_api(void) {
    /** setup **/
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *sttc = secp256k1_context_clone(secp256k1_context_no_precomp);
    secp256k1_batch *batch_none;
    secp256k1_batch *batch_sign;
    secp256k1_batch *batch_vrfy;
    secp256k1_batch *batch_both;
    secp256k1_batch *batch_sttc;
    int ecount;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sttc, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sttc, counting_illegal_callback_fn, &ecount);

    /** main test body **/
    /* todo: need to add tests for 1/4th, 3/4th of MAX_TERMS size? */
    ecount = 0;
    batch_none = secp256k1_batch_create(none, MAX_TERMS);
    CHECK(batch_none != NULL);
    CHECK(ecount == 0);
    batch_sign = secp256k1_batch_create(sign, MAX_TERMS/2);
    CHECK(batch_sign != NULL);
    CHECK(ecount == 0);
    batch_vrfy = secp256k1_batch_create(vrfy, MAX_TERMS-1);
    CHECK(batch_vrfy != NULL);
    CHECK(ecount == 0);
    batch_both = secp256k1_batch_create(both, 1);
    CHECK(batch_both != NULL);
    CHECK(ecount == 0);
    /* ARG_CHECK(max_terms != 0) in `batch_create` should fail*/
    batch_sttc = secp256k1_batch_create(sttc, 0);
    CHECK(batch_sttc == NULL);
    CHECK(ecount == 1);
    /* ARG_CHECK(max_terms <= SIZE_MAX/2) in `batch_create` should fail*/
    batch_sttc = secp256k1_batch_create(sttc, SIZE_MAX - 1);
    CHECK(batch_sttc == NULL);
    CHECK(ecount == 2);

    ecount = 0;
    CHECK(secp256k1_batch_verify(none, batch_none) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_batch_verify(sign, batch_sign) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_batch_verify(vrfy, batch_vrfy) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_batch_verify(both, batch_both) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_batch_verify(sttc, NULL) == 0);
    CHECK(ecount == 1);

    ecount = 0;
    secp256k1_batch_destroy(none, batch_none);
    CHECK(ecount == 0);
    secp256k1_batch_destroy(sign, batch_sign);
    CHECK(ecount == 0);
    secp256k1_batch_destroy(vrfy, batch_vrfy);
    CHECK(ecount == 0);
    secp256k1_batch_destroy(both, batch_both);
    CHECK(ecount == 0);
    secp256k1_batch_destroy(sttc, NULL);
    CHECK(ecount == 0);

    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
    secp256k1_context_destroy(sttc);
}


void run_batch_tests(void) {
    test_batch_api();
    test_batch_sha256_tagged();
}

#endif /* SECP256K1_MODULE_BATCH_TESTS_H */
