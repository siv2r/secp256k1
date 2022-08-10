#ifndef SECP256K1_DEBUG_BATCH_MAIN_H
#define SECP256K1_DEBUG_BATCH_MAIN_H

#include <stdio.h>
#include "../../debug_main.h"

/* static void print_batch(const secp256k1_batch *batch) {
    size_t i;

    printf("batch_res: %d\n", batch->result);
    printf("batch_cap: %lu\n", batch->capacity);
    printf("batch_len: %lu\n", batch->len);
    printf("batch_scg: ");
    print_scalar(&batch->sc_g);
    printf("\n%lu scalars:", batch->len);
    for (i = 0; i < batch->len; i++) {
        printf("\n");
        print_scalar(&batch->scalars[i]);
    }
    printf("\n%lu points:", batch->len);
    for (i = 0; i < batch->len; i++) {
        printf("\n");
        print_gej(&batch->points[i]);
    }
    printf("\nbatch_sha: ");
    print_sha(&batch->sha256);
} */

#endif /* DEBUG_BATCH */
