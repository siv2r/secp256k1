#ifndef SECP256K1_MODULE_EXTRAKEYS_BATCH_ADD_TESTS_IMPL_H
#define SECP256K1_MODULE_EXTRAKEYS_BATCH_ADD_TESTS_IMPL_H

#include "include/secp256k1_extrakeys.h"

/* Checks that a bit flip in the n_flip-th argument (that has n_bytes many
 * bytes) changes the hash function */
void batch_xonlypub_tweak_randomizer_gen_bitflip(secp256k1_sha256 *sha, unsigned char **args, size_t n_flip, size_t n_bytes) {
    unsigned char randomizers[2][32];
    secp256k1_sha256 sha_cpy;
    sha_cpy = *sha;
    secp256k1_batch_xonlypub_tweak_randomizer_gen(randomizers[0], &sha_cpy, args[0], args[1], args[2], args[3]);
    secp256k1_testrand_flip(args[n_flip], n_bytes);
    sha_cpy = *sha;
    secp256k1_batch_xonlypub_tweak_randomizer_gen(randomizers[1], &sha_cpy, args[0], args[1], args[2], args[3]);
    CHECK(secp256k1_memcmp_var(randomizers[0], randomizers[1], 32) != 0);
}

void run_batch_xonlypub_tweak_randomizer_gen_tests(void) {
    secp256k1_sha256 sha;
    size_t n_checks = 20;
    unsigned char tweaked_pk[32];
    unsigned char tweaked_pk_parity;
    unsigned char tweak[32];
    unsigned char internal_pk[33];
    unsigned char *args[4];
    size_t i; /* loops through n_checks */
    int j; /* loops through count */

    secp256k1_batch_sha256_tagged(&sha);

    for (i = 0; i < n_checks; i++) {
        uint8_t temp_rand;

        /* generate i-th tweak check data */
        secp256k1_testrand256(tweaked_pk);
        tweaked_pk_parity = (unsigned char) secp256k1_testrand_int(2);
        secp256k1_testrand256(tweak);
        secp256k1_testrand256(&internal_pk[1]);
        temp_rand = secp256k1_testrand_int(2) + 2; /* randomly choose 2 or 3 */
        internal_pk[0] = (unsigned char)temp_rand;

        /* check bitflip in any argument results in generates randomizers */
        args[0] = tweaked_pk;
        args[1] = &tweaked_pk_parity;
        args[2] = internal_pk;
        args[3] = tweak;

        for (j = 0; j < count; j++) {
            batch_xonlypub_tweak_randomizer_gen_bitflip(&sha, args, 0, 32);
            batch_xonlypub_tweak_randomizer_gen_bitflip(&sha, args, 1, 1);
            batch_xonlypub_tweak_randomizer_gen_bitflip(&sha, args, 2, 32);
            batch_xonlypub_tweak_randomizer_gen_bitflip(&sha, args, 3, 33);
        }

        /* write i-th tweak check data to the sha object
         * this is required for generating the next randomizer */
        secp256k1_sha256_write(&sha, tweaked_pk, 32);
        secp256k1_sha256_write(&sha, &tweaked_pk_parity, 1);
        secp256k1_sha256_write(&sha, tweak, 32);
        secp256k1_sha256_write(&sha, internal_pk, 33);
    }

}

void run_batch_add_xonlypub_tweak_tests(void) {
    run_batch_xonlypub_tweak_randomizer_gen_tests();
}


#endif /* SECP256K1_MODULE_EXTRAKEYS_BATCH_ADD_TESTS_IMPL_H */
