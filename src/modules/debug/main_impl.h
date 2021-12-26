#ifndef SECP256K1_MODULE_DEBUG_MAIN_H
#define SECP256K1_MODULE_DEBUG_MAIN_H

static void print_sha(secp256k1_sha256 *sha) {
    size_t i;
    for (i = 0; i < 8; i++) {
        printf("%02x ", sha->s[i]);
    }
    printf("\n");
}

static void print_buf(const unsigned char *buf, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");
}
static void print_scalar(const secp256k1_scalar *x) {
    unsigned char buf32[32];
    secp256k1_scalar_get_b32(buf32, x);
    print_buf(buf32, 32);
}

static void print_ge(secp256k1_ge *p) {
    unsigned char buf33[33];
    size_t size = 33;
    secp256k1_eckey_pubkey_serialize(p, buf33, &size, 1);
    print_buf(buf33, 33);
}

#ifdef ENABLE_MODULE_SCHNORRSIG

static void print_xonly(const secp256k1_context *ctx, const secp256k1_xonly_pubkey *p) {
    unsigned char buf32[32];
    secp256k1_xonly_pubkey_serialize(ctx, buf32, p);
    print_buf(buf32, 32);
}

#endif /* ENABLE_MODULE_SCHNORRSIG */

static void print_pubkey(const secp256k1_context *ctx, const secp256k1_pubkey *p) {
    unsigned char buf[33];
    size_t size = 33;

    secp256k1_ec_pubkey_serialize(ctx, buf, &size, p, SECP256K1_EC_COMPRESSED);
    print_buf(buf, 33);
}

/* TODO: 32 byte even or odd?? */
/* TODO: 32 byte char to int */

#endif /* SECP256K1_MODULE_DEBUG */