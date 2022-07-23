#ifndef SECP256K1_MODULE_BATCH_TESTS_H
#define SECP256K1_MODULE_BATCH_TESTS_H

#include "include/secp256k1_batch.h"

#define MAX_TERMS 20
#define N_SIGS 10
#define N_TWK_CHECKS 10

/* Tests for the equality of two sha256 structs. This function only produces a
 * correct result if an integer multiple of 64 many bytes have been written
 * into the hash functions. */
void test_batch_sha256_eq(const secp256k1_sha256 *sha1, const secp256k1_sha256 *sha2) {
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
    test_batch_sha256_eq(&sha, &sha_optimized);
}

void test_batch_api(void) {
    unsigned char sk[32];
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pk;
    secp256k1_xonly_pubkey zero_pk;
    /* schnorr verification data */
    unsigned char msg[N_SIGS][32];
    unsigned char sig[N_SIGS][64];
    /* xonly pubkey tweak checks data */
    unsigned char tweaked_pk[N_TWK_CHECKS][32];
    int tweaked_pk_parity[N_TWK_CHECKS];
    unsigned char tweak[N_TWK_CHECKS][32];
    secp256k1_pubkey tmp_pk;
    secp256k1_xonly_pubkey tmp_xonly_pk;
    unsigned char overflows[32];
    /* context and batch setup */
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
    size_t i;

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

    /* generate keypair data */
    secp256k1_testrand256(sk);
    CHECK(secp256k1_keypair_create(ctx, &keypair, sk) == 1);
    CHECK(secp256k1_keypair_xonly_pub(ctx, &pk, NULL, &keypair) == 1);
    memset(&zero_pk, 0, sizeof(zero_pk));

    /* generate N_SIGS schnorr verify data (msg, sig) */
    for (i = 0; i < N_SIGS; i++) {
        secp256k1_testrand256(msg[i]);
        CHECK(secp256k1_schnorrsig_sign32(ctx, sig[i], msg[i], &keypair, NULL) == 1);
        CHECK(secp256k1_schnorrsig_verify(ctx, sig[i], msg[i], sizeof(msg[i]), &pk));
    }

    /* generate N_TWK_CHECKS tweak check data (tweaked_pk, tweaked_pk_parity, tweak) */
    memset(overflows, 0xff, sizeof(overflows));
    for (i = 0; i < N_TWK_CHECKS; i++) {
        secp256k1_testrand256(tweak[i]);
        CHECK(secp256k1_xonly_pubkey_tweak_add(ctx, &tmp_pk, &pk, tweak[i]));
        CHECK(secp256k1_xonly_pubkey_from_pubkey(ctx, &tmp_xonly_pk, &tweaked_pk_parity[i], &tmp_pk));
        CHECK(secp256k1_xonly_pubkey_serialize(ctx, tweaked_pk[i], &tmp_xonly_pk));
        CHECK(secp256k1_xonly_pubkey_tweak_add_check(ctx, tweaked_pk[i], tweaked_pk_parity[i], &pk, tweak[i]));
    }


    /** main test body **/
    /* todo: need to add tests for 1/4th, 3/4th of MAX_TERMS size? */
    ecount = 0;
    batch_none = secp256k1_batch_create(none, 1, NULL);
    CHECK(batch_none != NULL);
    CHECK(ecount == 0);
    batch_sign = secp256k1_batch_create(sign, MAX_TERMS/2, NULL);
    CHECK(batch_sign != NULL);
    CHECK(ecount == 0);
    batch_vrfy = secp256k1_batch_create(vrfy, MAX_TERMS-1, NULL);
    CHECK(batch_vrfy != NULL);
    CHECK(ecount == 0);
    batch_both = secp256k1_batch_create(both, MAX_TERMS, NULL);
    CHECK(batch_both != NULL);
    CHECK(ecount == 0);
    /* ARG_CHECK(max_terms != 0) in `batch_create` should fail*/
    batch_sttc = secp256k1_batch_create(sttc, 0, NULL);
    CHECK(batch_sttc == NULL);
    CHECK(ecount == 1);

#ifdef ENABLE_MODULE_SCHNORRSIG
    /* secp256k1_batch_add tests for batch_none */
    ecount = 0;
    CHECK(secp256k1_batch_usable(none, batch_none) == 1);
    CHECK(secp256k1_batch_add_schnorrsig(none, batch_none, NULL, msg[0], sizeof(msg[0]), &pk) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_batch_usable(none, batch_none) == 1);
    CHECK(secp256k1_batch_add_schnorrsig(none, batch_none, sig[0], NULL, sizeof(msg[0]), &pk) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_batch_usable(none, batch_none) == 1);
    /* todo: this batch_add is not extracting point correctly (verify fails)*/
    CHECK(secp256k1_batch_add_schnorrsig(none, batch_none, sig[0], NULL, 0, &pk) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_batch_usable(none, batch_none) == 1);
    CHECK(secp256k1_batch_add_schnorrsig(none, batch_none, sig[0], msg[0], sizeof(msg[0]), NULL) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_batch_usable(none, batch_none) == 1);
    CHECK(secp256k1_batch_add_schnorrsig(none, batch_none, sig[0], msg[0], sizeof(msg[0]), &zero_pk) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_batch_usable(none, batch_none) == 1);
    CHECK(secp256k1_batch_add_schnorrsig(none, NULL, sig[0], msg[0], sizeof(msg[0]), &pk) == 0);
    CHECK(ecount == 5);
#endif

#ifdef ENABLE_MODULE_EXTRAKEYS
    /* secp256k1_batch_add_tests for batch_sign */
    ecount = 0;
    CHECK(secp256k1_batch_usable(sign, batch_sign) == 1);
    CHECK(secp256k1_batch_add_xonlypub_tweak_check(sign, batch_sign, NULL, tweaked_pk_parity[0], &pk, tweak[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_batch_usable(sign, batch_sign) == 1);
    CHECK(secp256k1_batch_add_xonlypub_tweak_check(sign, batch_sign, tweaked_pk[0], tweaked_pk_parity[0], NULL, tweak[0]) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_batch_usable(sign, batch_sign) == 1);
    CHECK(secp256k1_batch_add_xonlypub_tweak_check(sign, batch_sign, tweaked_pk[0], tweaked_pk_parity[0], &pk, NULL) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_batch_usable(sign, batch_sign) == 1);
    CHECK(secp256k1_batch_add_xonlypub_tweak_check(sign, NULL, tweaked_pk[0], tweaked_pk_parity[0], &pk, tweak[0]) == 0);
    CHECK(ecount == 4);
    /* overflowing tweak not allowed */
    CHECK(secp256k1_batch_usable(sign, batch_sign) == 1);
    CHECK(secp256k1_batch_add_xonlypub_tweak_check(sign, batch_sign, tweaked_pk[0], tweaked_pk_parity[0], &pk, overflows) == 0);
    CHECK(ecount == 4);
    /* x-coordinate of tweaked pubkey should be less than prime order */
    CHECK(secp256k1_batch_usable(sign, batch_sign) == 1);
    CHECK(secp256k1_batch_add_xonlypub_tweak_check(sign, batch_sign, overflows, tweaked_pk_parity[0], &pk, tweak[0]) == 0);
    CHECK(ecount == 4);
    /* batch_verify should fail for incorrect tweak */
    CHECK(secp256k1_batch_usable(sign, batch_sign) == 1);
    CHECK(secp256k1_batch_add_xonlypub_tweak_check(sign, batch_sign, tweaked_pk[0], !tweaked_pk_parity[0], &pk, tweak[0]) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_batch_verify(sign, batch_sign) == 0);
    CHECK(ecount == 4);
    /* passing batch_add_* should not accept invalid batch object */
    CHECK(secp256k1_batch_usable(sign, batch_sign) == 0);
    CHECK(secp256k1_batch_add_xonlypub_tweak_check(sign, batch_sign, tweaked_pk[0], tweaked_pk_parity[0], &pk, tweak[0]) == 0);
    CHECK(ecount == 4);
#endif

    /* secp256k1_batch_add_tests for batch_vrfy */
    ecount = 0;

#if defined(ENABLE_MODULE_SCHNORRSIG) && defined(ENABLE_MODULE_EXTRAKEYS)
    /* secp256k1_batch_add_tests for batch_both */
    ecount = 0;
    for (i = 0; i < N_SIGS; i++) {
        CHECK(secp256k1_batch_usable(ctx, batch_both) == 1);
        CHECK(secp256k1_batch_add_schnorrsig(ctx, batch_both, sig[i], msg[i], sizeof(msg[i]), &pk) == 1);
    }
    for (i = 0; i < N_TWK_CHECKS; i++) {
        CHECK(secp256k1_batch_usable(ctx, batch_both));
        CHECK(secp256k1_batch_add_xonlypub_tweak_check(ctx, batch_both, tweaked_pk[i], tweaked_pk_parity[i], &pk, tweak[i]));
    }
#endif

    ecount = 0;
    CHECK(secp256k1_batch_verify(none, batch_none) == 0);
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
