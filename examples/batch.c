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

/* generate key pair required for sign and verify */
int create_keypair(secp256k1_context *ctx) {
    while(1) {
        if (!fill_random(sk, sizeof(sk))) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (secp256k1_keypair_create(ctx, &keypair, sk)) {
            break;
        }
    }
    if (!secp256k1_keypair_xonly_pub(ctx, &pk, NULL, &keypair)) {
        return 0;
    }

    return 1;
}

/* create valid schnorrsigs for N_SIGS random messages */
int generate_schnorrsigs(secp256k1_context *ctx) {
    size_t i;

    for (i = 0; i < N_SIGS; i++) {
        if(!fill_random(msg[i], sizeof(msg[i]))) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        assert(secp256k1_schnorrsig_sign32(ctx, sig[i], msg[i], &keypair, NULL));
        assert(secp256k1_schnorrsig_verify(ctx, sig[i], msg[i], sizeof(msg[i]), &pk));
    }

    return 1;
}

int main(void) {
    int ret;
    size_t i;
    /* batch_context uses secp256k1_context only for the error callback function*/
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_batch_context *batch_ctx = secp256k1_batch_context_create(ctx, N_SIGS-5);

    assert(ctx != NULL);
    assert(batch_ctx != NULL);

    /* key pair generation */
    printf("Creating a key pair.......................");
    if(!create_keypair(ctx)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");

    /* create schnorrsigs for N_SIGS random messages */
    printf("Signing messages..........................");
    if(!generate_schnorrsigs(ctx)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");

    printf("Adding signatures to the batch context....");
    for (i = 0; i < N_SIGS; i++) {
        ret = secp256k1_batch_context_add_schnorrsig(ctx, batch_ctx, sig[i], msg[i], sizeof(msg[i]), &pk);
        if(!ret) {
            printf("FAILED\n");
            return 1;
        }
    }
    printf("ok\n");

    printf("Verifying the batch context...............");
    if(!secp256k1_batch_context_verify(ctx, batch_ctx)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");

    secp256k1_batch_context_destroy(ctx, batch_ctx);
    secp256k1_context_destroy(ctx);

    return 0;
}