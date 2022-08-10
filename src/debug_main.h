#ifndef SECP256K1_DEBUG_MAIN_H
#define SECP256K1_DEBUG_MAIN_H

/** Every function prints the data as inline.
 *  If you want the outpu on a newline, You need
 *  to add '\n' before and after the function call
 */

static void print_sha(const secp256k1_sha256 *sha) {
    size_t i;
    for (i = 0; i < 8; i++) {
        printf("%02x ", sha->s[i]);
    }
}

static void print_buf(const unsigned char *buf, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        printf("%02x", buf[i]);
        if (i % 4 == 3) {
            /* printf(" "); */
        }
    }
}
static void print_scalar(const secp256k1_scalar *x) {
    unsigned char buf32[32];
    /**
     *this function is needed since, the scalar has different structure on
     *64 bit vs 32 bit system, Hence, it is defined in both `scalar_64x4_impl.h`
     *and in `scalar_32x8_impl.h`
     */
    secp256k1_scalar_get_b32(buf32, x);
    print_buf(buf32, 32);
}

/**
 *inp must be normalized. If you want to print an fe without normalization
 *do printf("%lx", inp->n[i]), i = 0...4
 */
static void print_fe(const secp256k1_fe *inp) {
    unsigned char value[32];

    secp256k1_fe_normalize_var(inp);
    secp256k1_fe_get_b32(value, inp);
    print_buf(value, 32);

#ifdef VERIFY
    printf(", %d (mag), %d (normal)", inp->magnitude, inp->normalized);
#endif
}

/*
 *NOTE: `random_fe` function is already present in tests.c (under field tests)
 */

static unsigned char hex_char_to_buf(const unsigned char inp) {
    if (inp >= '0' && inp <= '9') {
        return inp - '0';
    } else if (inp >= 'A' && inp <= 'F') {
        return inp - 'A' + 10;
    } else if (inp >= 'a' && inp <= 'f') {
        return inp - 'a' + 10;
    }
    fprintf(stderr, "hex string should contain only 0-9,a-f and A-F");

    return -1;
}

/** given hex string is stored as big endian bytes in unsinged char
 *  TODO: is there a way to set the out pointer by passing it through arguments?
 */
static unsigned char *hex_str_to_buf(int *out_len, const unsigned char *inp,
                                     int inp_len) {
    int i = 0, j = 0, temp = (inp_len + 1) / 2; /* output string length */
    unsigned char *out = malloc(temp * sizeof(unsigned char));
    unsigned char low, high;

    if (out_len != NULL) {
        *out_len = temp;
    }

    if (inp_len % 2) {
        out[j] = hex_char_to_buf(inp[i]);
        i++;
        j++;
    }

    /* the remaining hex string length will be even */
    while (i < inp_len && j < temp) {
        low = hex_char_to_buf(inp[i + 1]);
        high = hex_char_to_buf(inp[i]);

        out[j] = low | (high << 4);
        i += 2;
        j++;
    }

    return out;
}

static void print_ge(secp256k1_ge *inp) {
    /* print the x and y coordinates */
    printf("X: ");
    print_fe(&inp->x); /* internally normalizes the field element, then prints */
    printf("\nY: ");
    print_fe(&inp->y); /* internally normalizes the field element, then prints */
    printf("\ninf: %d", inp->infinity);
}

static void print_ge_serialized(secp256k1_ge *p) {
    unsigned char buf33[33];
    size_t size = 33;
    secp256k1_eckey_pubkey_serialize(p, buf33, &size, 1);
    print_buf(buf33, 33);
}

static void print_gej(secp256k1_gej *inp) {
    secp256k1_ge tmp;
    secp256k1_ge_set_gej(&tmp, inp);
    print_ge(&tmp);
}

static void print_pubkey(const secp256k1_context *ctx,
                         const secp256k1_pubkey *p) {
    unsigned char buf[33];
    size_t size = 33;

    secp256k1_ec_pubkey_serialize(ctx, buf, &size, p, SECP256K1_EC_COMPRESSED);
    print_buf(buf, 33);
}

/* TODO: 32 byte even or odd?? */
/* TODO: 32 byte char to int */

#endif /* SECP256K1_DEBUG_MAIN */