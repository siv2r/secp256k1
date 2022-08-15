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

/* Helper for function test_schnorrsig_sign_batch_verify
 * Checks that batch_verify fails after flipping random byte. */
void test_schnorrsig_sign_verify_check_batch(secp256k1_batch *batch, unsigned char *sig64, unsigned char *msg, size_t msglen, secp256k1_xonly_pubkey *pk) {
    int ret;

    CHECK(secp256k1_batch_usable(ctx, batch));
    /* filling a random byte (in msg or sig) can cause the following:
     *     1. unparsable msg or sig - here, batch_add_schnorrsig fails and batch_verify passes
     *     2. invalid schnorr eqn   - here, batch_verify fails and batch_add_schnorrsig passes
     */
    ret = secp256k1_batch_add_schnorrsig(ctx, batch, sig64, msg, msglen, pk);
    if (ret == 0) {
        CHECK(secp256k1_batch_verify(ctx, batch) == 1);
    } else if (ret == 1) {
        CHECK(secp256k1_batch_verify(ctx, batch) == 0);
    }
}

#define N_SIGS 3
/* Creates N_SIGS valid signatures and verifies them with batch_verify.
 * Then flips some bits and checks that verification now fails. This is a
 * variation of `test_schnorrsig_sign_verify` (in schnorrsig/tests_impl.h) */
void test_schnorrsig_sign_batch_verify(void) {
    unsigned char sk[32];
    unsigned char msg[N_SIGS][32];
    unsigned char sig[N_SIGS][64];
    size_t i;
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pk;
    secp256k1_scalar s;
    secp256k1_batch *batch[N_SIGS + 1];
    secp256k1_batch *batch_fail1;
    secp256k1_batch *batch_fail2;

    /* batch[0] will be used where batch_add and batch_verify
     * are expected to succed */
    batch[0] = secp256k1_batch_create(ctx, N_SIGS, NULL);
    for (i = 0; i < N_SIGS; i++) {
        batch[i+1] = secp256k1_batch_create(ctx, 1, NULL);
    }
    batch_fail1 = secp256k1_batch_create(ctx, 1, NULL);
    batch_fail2 = secp256k1_batch_create(ctx, 1, NULL);

    secp256k1_testrand256(sk);
    CHECK(secp256k1_keypair_create(ctx, &keypair, sk));
    CHECK(secp256k1_keypair_xonly_pub(ctx, &pk, NULL, &keypair));

    for (i = 0; i < N_SIGS; i++) {
        secp256k1_testrand256(msg[i]);
        CHECK(secp256k1_schnorrsig_sign32(ctx, sig[i], msg[i], &keypair, NULL));
        CHECK(secp256k1_batch_usable(ctx, batch[0]));
        CHECK(secp256k1_batch_add_schnorrsig(ctx, batch[0], sig[i], msg[i], sizeof(msg[i]), &pk));
    }
    CHECK(secp256k1_batch_verify(ctx, batch[0]));

    {
        /* Flip a few bits in the signature and in the message and check that
         * verify and verify_batch (TODO) fail */
        size_t sig_idx = secp256k1_testrand_int(N_SIGS);
        size_t byte_idx = secp256k1_testrand_bits(5);
        unsigned char xorbyte = secp256k1_testrand_int(254)+1;

        sig[sig_idx][byte_idx] ^= xorbyte;
        test_schnorrsig_sign_verify_check_batch(batch[1], sig[sig_idx], msg[sig_idx], sizeof(msg[sig_idx]), &pk);
        sig[sig_idx][byte_idx] ^= xorbyte;

        byte_idx = secp256k1_testrand_bits(5);
        sig[sig_idx][32+byte_idx] ^= xorbyte;
        test_schnorrsig_sign_verify_check_batch(batch[2], sig[sig_idx], msg[sig_idx], sizeof(msg[sig_idx]), &pk);
        sig[sig_idx][32+byte_idx] ^= xorbyte;

        byte_idx = secp256k1_testrand_bits(5);
        msg[sig_idx][byte_idx] ^= xorbyte;
        test_schnorrsig_sign_verify_check_batch(batch[3], sig[sig_idx], msg[sig_idx], sizeof(msg[sig_idx]), &pk);
        msg[sig_idx][byte_idx] ^= xorbyte;

        /* Check that above bitflips have been reversed correctly */
        CHECK(secp256k1_schnorrsig_verify(ctx, sig[sig_idx], msg[sig_idx], sizeof(msg[sig_idx]), &pk));
    }

    /* Test overflowing s */
    CHECK(secp256k1_schnorrsig_sign32(ctx, sig[0], msg[0], &keypair, NULL));
    CHECK(secp256k1_batch_add_schnorrsig(ctx, batch[0], sig[0], msg[0], sizeof(msg[0]), &pk) == 1);
    memset(&sig[0][32], 0xFF, 32);
    CHECK(secp256k1_batch_add_schnorrsig(ctx, batch[0], sig[0], msg[0], sizeof(msg[0]), &pk) == 0);

    /* Test negative s */
    CHECK(secp256k1_schnorrsig_sign32(ctx, sig[0], msg[0], &keypair, NULL));
    CHECK(secp256k1_batch_add_schnorrsig(ctx, batch[0], sig[0], msg[0], sizeof(msg[0]), &pk) == 1);
    secp256k1_scalar_set_b32(&s, &sig[0][32], NULL);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_scalar_get_b32(&sig[0][32], &s);
    CHECK(secp256k1_batch_add_schnorrsig(ctx, batch_fail1, sig[0], msg[0], sizeof(msg[0]), &pk) == 1);
    CHECK(secp256k1_batch_verify(ctx, batch_fail1) == 0);

    /* The empty message can be signed & verified */
    CHECK(secp256k1_schnorrsig_sign_custom(ctx, sig[0], NULL, 0, &keypair, NULL) == 1);
    CHECK(secp256k1_batch_usable(ctx, batch[0]) == 1);
    CHECK(secp256k1_batch_add_schnorrsig(ctx, batch[0], sig[0], NULL, 0, &pk) == 1);
    CHECK(secp256k1_batch_verify(ctx, batch[0]) == 1);

    {
        /* Test varying message lengths */
        unsigned char msg_large[32 * 8];
        uint32_t msglen  = secp256k1_testrand_int(sizeof(msg_large));
        for (i = 0; i < sizeof(msg_large); i += 32) {
            secp256k1_testrand256(&msg_large[i]);
        }
        CHECK(secp256k1_schnorrsig_sign_custom(ctx, sig[0], msg_large, msglen, &keypair, NULL) == 1);
        CHECK(secp256k1_batch_usable(ctx, batch[0]) == 1);
        CHECK(secp256k1_batch_add_schnorrsig(ctx, batch[0], sig[0], msg_large, msglen, &pk) == 1);
        CHECK(secp256k1_batch_verify(ctx, batch[0]) == 1);
        /* batch_add fails for a random wrong message length */
        msglen = (msglen + (sizeof(msg_large) - 1)) % sizeof(msg_large);
        CHECK(secp256k1_batch_usable(ctx, batch_fail2) == 1);
        CHECK(secp256k1_batch_add_schnorrsig(ctx, batch_fail2, sig[0], msg_large, msglen, &pk) == 1);
        CHECK(secp256k1_batch_verify(ctx, batch_fail2) == 0);
    }

    /* Destroy the batch objects */
    for (i = 0; i < N_SIGS+1; i++) {
        secp256k1_batch_destroy(ctx, batch[i]);
    }
    secp256k1_batch_destroy(ctx, batch_fail1);
    secp256k1_batch_destroy(ctx, batch_fail2);
}
#undef N_SIGS

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
    int i;

    run_batch_schnorrsig_randomizer_gen_tests();
    test_batch_add_schnorrsig_api();
    for (i = 0; i < count; i++) {
        test_schnorrsig_sign_batch_verify();
    }
}


#endif /* SECP256K1_MODULE_SCHNORRSIG_BATCH_ADD_TESTS_IMPL_H */
