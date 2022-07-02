#ifndef SECP256K1_MODULE_SCHNORRSIG_BATCH_ADD_TESTS_IMPL_H
#define SECP256K1_MODULE_SCHNORRSIG_BATCH_ADD_TESTS_IMPL_H

#include "include/secp256k1_schnorrsig.h"

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

void run_batch_add_schnorrsig_tests(void) {
    run_batch_schnorrsig_randomizer_gen_tests();
}


#endif /* SECP256K1_MODULE_SCHNORRSIG_BATCH_ADD_TESTS_IMPL_H */
