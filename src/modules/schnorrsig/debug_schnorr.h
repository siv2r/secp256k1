#ifndef SECP256K1_DEBUG_SCHNORRSIG_MAIN_H
#define SECP256K1_DEBUG_SCHNORRSIG_MAIN_H

/**
 * todo: add this to schnorrsig/main_impl.h
*/

static void print_xonly(const secp256k1_context *ctx, const secp256k1_xonly_pubkey *p) {
    unsigned char buf32[32];
    secp256k1_xonly_pubkey_serialize(ctx, buf32, p);
    print_buf(buf32, 32);
}

#endif /* DEBUG_SCHNORRSIG */
