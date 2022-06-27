#ifndef SECP256K1_MODULE_BATCH_TESTS_H
#define SECP256K1_MODULE_BATCH_TESTS_H

#include "include/secp256k1_batch.h"

#define MAX_TERMS 10

void test_batch_api(void) {
    /** setup **/
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_batch *batch_none;
    secp256k1_batch *batch_sign;
    secp256k1_batch *batch_vrfy;
    secp256k1_batch *batch_both;
    int ecount;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);

    /** main test body **/
    ecount = 0;
    batch_none = secp256k1_batch_create(none, MAX_TERMS);
    CHECK(batch_none != NULL);
    CHECK(ecount == 0);
    batch_sign = secp256k1_batch_create(sign, MAX_TERMS);
    CHECK(batch_sign != NULL);
    CHECK(ecount == 0);
    batch_vrfy = secp256k1_batch_create(vrfy, MAX_TERMS);
    CHECK(batch_vrfy != NULL);
    CHECK(ecount == 0);
    batch_both = secp256k1_batch_create(both, MAX_TERMS);
    CHECK(batch_both != NULL);
    CHECK(ecount == 0);

    ecount = 0;
    CHECK(secp256k1_batch_verify(none, batch_none) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_batch_verify(sign, batch_sign) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_batch_verify(vrfy, batch_vrfy) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_batch_verify(both, batch_both) == 1);
    CHECK(ecount == 0);

    ecount = 0;
    secp256k1_batch_destroy(none, batch_none);
    CHECK(ecount == 0);
    secp256k1_batch_destroy(sign, batch_sign);
    CHECK(ecount == 0);
    secp256k1_batch_destroy(vrfy, batch_vrfy);
    CHECK(ecount == 0);
    secp256k1_batch_destroy(both, batch_both);
    CHECK(ecount == 0);

    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
}


void run_batch_tests(void) {
    test_batch_api();
}

#endif /* SECP256K1_MODULE_BATCH_TESTS_H */
