#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

int main(void) {
    /* batch_context uses secp256k1_context only for the error callback function*/
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    
    secp256k1_batch_context *batch_ctx = secp256k1_batch_context_create(ctx, 3);
    assert(batch_ctx != NULL);
    assert(secp256k1_batch_context_verify(ctx, batch_ctx) == 0);
    secp256k1_batch_context_destroy(ctx, batch_ctx);

    secp256k1_context_destroy(ctx);

    printf("Batch example completed...\n");
    return 0;
}