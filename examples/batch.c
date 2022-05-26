#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

#include "random.h"

/* signature, msg and key pair data */
#define N_SIGS 10
unsigned char sk[32];
unsigned char msg[N_SIGS][32];
unsigned char sig[N_SIGS][64];
secp256k1_keypair keypair;
secp256k1_xonly_pubkey pk;

void generate_inp_data(secp256k1_context *ctx) {
    size_t i;
    /* key pair generation */
    assert(fill_random(sk, sizeof(sk)));
    assert(secp256k1_keypair_create(ctx, &keypair, sk));
    assert(secp256k1_keypair_xonly_pub(ctx, &pk, NULL, &keypair));

    /* create schnorrsig for N_SIGS random messages */
    for (i = 0; i < N_SIGS; i++) {
        assert(fill_random(msg[i], sizeof(msg[i])));
        assert(secp256k1_schnorrsig_sign32(ctx, sig[i], msg[i], &keypair, NULL));
        assert(secp256k1_schnorrsig_verify(ctx, sig[i], msg[i], sizeof(msg[i]), &pk));
    }
}

int main(void) {
    int ret;
    /* batch_context uses secp256k1_context only for the error callback function*/
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_batch_context *batch_ctx = secp256k1_batch_context_create(ctx, N_SIGS);

    generate_inp_data(ctx);

    ret = secp256k1_batch_context_add_schnorrsig(ctx, batch_ctx, sig[0], msg[0], sizeof(msg[0]), &pk);
    assert(ret);
    assert(secp256k1_batch_context_verify(ctx, batch_ctx));

    secp256k1_batch_context_destroy(ctx, batch_ctx);
    secp256k1_context_destroy(ctx);

    printf("Batch example completed...\n");
    return 0;
}