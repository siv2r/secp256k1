#ifndef SECP256K1_MODULE_SCHNORRSIG_BATCH_ADD_TESTS_IMPL_H
#define SECP256K1_MODULE_SCHNORRSIG_BATCH_ADD_TESTS_IMPL_H

#include "../../../include/secp256k1_schnorrsig.h"
#include "../../../include/secp256k1_batch.h"
#include "../../../include/secp256k1_schnorrsig_batch.h"

/* Checks that a bit flip in the n_flip-th argument (that has n_bytes many
 * bytes) changes the hash function */
void batch_schnorrsig_randomizer_gen_bitflip(secp256k1_sha256 *sha, unsigned char **args, size_t n_flip, size_t n_bytes, size_t msglen) {
    unsigned char randomizers[2][32];
    secp256k1_sha256 sha_cpy;
    sha_cpy = *sha;
    secp256k1_batch_schnorrsig_randomizer_gen(randomizers[0], &sha_cpy, args[0], args[1], msglen, args[2]);
    secp256k1_testrand_flip(args[n_flip], n_bytes);
    sha_cpy = *sha;
    secp256k1_batch_schnorrsig_randomizer_gen(randomizers[1], &sha_cpy, args[0], args[1], msglen, args[2]);
    CHECK(secp256k1_memcmp_var(randomizers[0], randomizers[1], 32) != 0);
}

void run_batch_schnorrsig_randomizer_gen_tests(void) {
    secp256k1_sha256 sha;
    size_t n_sigs = 20;
    unsigned char msg[32];
    size_t msglen = sizeof(msg);
    unsigned char sig[64];
    unsigned char compressed_pk[33];
    unsigned char *args[3];
    size_t i; /* loops through n_sigs */
    int j; /* loops through count */

    secp256k1_batch_sha256_tagged(&sha);

    for (i = 0; i < n_sigs; i++) {
        uint8_t temp_rand;
        unsigned char randomizer[32];
        /* batch_schnorrsig_randomizer_gen func modifies the sha object passed
         * so, pass the copied obj instead of original */
        secp256k1_sha256 sha_cpy;

        /* generate i-th schnorrsig verify data */
        secp256k1_testrand256(msg);
        secp256k1_testrand256(&sig[0]);
        secp256k1_testrand256(&sig[32]);
        secp256k1_testrand256(&compressed_pk[1]);
        temp_rand = secp256k1_testrand_int(2) + 2; /* randomly choose 2 or 3 */
        compressed_pk[0] = (unsigned char)temp_rand;

        /* check that bitflip in an argument results in different nonces */
        args[0] = sig;
        args[1] = msg;
        args[2] = compressed_pk;

        for (j = 0; j < count; j++) {
            batch_schnorrsig_randomizer_gen_bitflip(&sha, args, 0, 64, msglen);
            batch_schnorrsig_randomizer_gen_bitflip(&sha, args, 1, 32, msglen);
            batch_schnorrsig_randomizer_gen_bitflip(&sha, args, 2, 33, msglen);
        }

        /* different msglen should generate different randomizers */
        sha_cpy = sha;
        secp256k1_batch_schnorrsig_randomizer_gen(randomizer, &sha_cpy, sig, msg, msglen, compressed_pk);

        for (j = 0; j < count; j++) {
            unsigned char randomizer2[32];
            uint32_t offset = secp256k1_testrand_int(msglen - 1);
            size_t msglen_tmp = (msglen + offset) % msglen;

            sha_cpy = sha;
            secp256k1_batch_schnorrsig_randomizer_gen(randomizer2, &sha_cpy, sig, msg, msglen_tmp, compressed_pk);
            CHECK(secp256k1_memcmp_var(randomizer, randomizer2, 32) != 0);
        }

        /* write i-th schnorrsig verify data to the sha object
         * this is required for generating the next randomizer */
        secp256k1_sha256_write(&sha, sig, 64);
        secp256k1_sha256_write(&sha, msg, msglen);
        secp256k1_sha256_write(&sha, compressed_pk, 33);
    }

}

void test_batch_add_schnorrsig_api(void) {
    unsigned char sk[32];
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pk;
    secp256k1_xonly_pubkey zero_pk;
    unsigned char msg[32];
    unsigned char sig[64];
    unsigned char nullmsg_sig[64];

    /** setup **/
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_batch *batch1 = secp256k1_batch_create(none, 1, NULL);
    /* batch2 is used when batch_add_schnorrsig is expected to fail */
    secp256k1_batch *batch2 = secp256k1_batch_create(none, 1, NULL);
    int ecount;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);

    /** generate keypair data **/
    secp256k1_testrand256(sk);
    CHECK(secp256k1_keypair_create(sign, &keypair, sk) == 1);
    CHECK(secp256k1_keypair_xonly_pub(sign, &pk, NULL, &keypair) == 1);
    memset(&zero_pk, 0, sizeof(zero_pk));

    /** generate a signature **/
    secp256k1_testrand256(msg);
    CHECK(secp256k1_schnorrsig_sign32(sign, sig, msg, &keypair, NULL) == 1);
    CHECK(secp256k1_schnorrsig_verify(vrfy, sig, msg, sizeof(msg), &pk));

    CHECK(batch1 != NULL);
    CHECK(batch2 != NULL);

    /** main test body **/
    ecount = 0;
    CHECK(secp256k1_batch_add_schnorrsig(none, batch1, sig, msg, sizeof(msg), &pk) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_batch_verify(none, batch1) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_batch_add_schnorrsig(none, batch2, NULL, msg, sizeof(msg), &pk) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_batch_add_schnorrsig(none, batch2, sig, NULL, sizeof(msg), &pk) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_batch_add_schnorrsig(none, batch2, sig, msg, sizeof(msg), NULL) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_batch_add_schnorrsig(none, batch2, sig, msg, sizeof(msg), &zero_pk) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_batch_add_schnorrsig(none, NULL, sig, msg, sizeof(msg), &pk) == 0);
    CHECK(ecount == 5);

    /** NULL msg with valid signature **/
    ecount = 0;
    CHECK(secp256k1_schnorrsig_sign_custom(sign, nullmsg_sig, NULL, 0, &keypair, NULL) == 1);
    CHECK(secp256k1_batch_usable(none, batch1) == 1);
    CHECK(secp256k1_batch_add_schnorrsig(none, batch1, nullmsg_sig, NULL, 0, &pk) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_batch_verify(none, batch1) == 1);

    /** NULL msg with invalid signature **/
    CHECK(secp256k1_batch_usable(none, batch2) == 1);
    CHECK(secp256k1_batch_add_schnorrsig(none, batch2, sig, NULL, 0, &pk) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_batch_verify(none, batch2) == 0);

    /** batch_add_ should ignore unusable batch object (i.e, batch->result = 0) **/
    ecount = 0;
    CHECK(secp256k1_batch_usable(none, batch2) == 0);
    CHECK(ecount == 0);
    CHECK(secp256k1_batch_add_schnorrsig(none, batch2, sig, msg, sizeof(msg), &pk) == 0);
    CHECK(ecount == 0);

    ecount = 0;
    secp256k1_batch_destroy(ctx, batch1);
    CHECK(ecount == 0);
    secp256k1_batch_destroy(ctx, batch2);
    CHECK(ecount == 0);

    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
}

void run_batch_add_schnorrsig_tests(void) {
    run_batch_schnorrsig_randomizer_gen_tests();
    test_batch_add_schnorrsig_api();
}


#endif /* SECP256K1_MODULE_SCHNORRSIG_BATCH_ADD_TESTS_IMPL_H */
