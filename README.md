libsecp256k1 debug setup - siv2r
============
- [`debug_main.h`](src/debug_main.h) contains the following debug functions:
    - `print_buf` - prints a buffer (or bytes) of any length in hexadecimal form
    - `print_sha` - prints a `secp256k1_sha256` object
    - `print_scalar` - prints a `secp256k1_scalar` object
    - `print_fe` - prints a `secp256k1_fe` object
        - NOTE: this function normalizes the input before printing it
        - if you don't want it to normalize, remove the `secp256k1_fe_normalize_var(inp)` line in function def
    - `print_ge` - prints a `secp256k1_ge` object
        - NOTE: this function normalizes the `x` and `y` coordinate before printing
    - `print_gej` - prints a `secp256k1_gej` object
        - NOTE: this function normalizes the `x` and `y` coordinate before printing
  - `print_pubkey` - prints the compressed form of a `secp256k1_pubkey`

- [`debug_schnorr.h`](src/modules/schnorrsig/debug_schnorr.h) contains the following debug functions:
    - `print_xonly` - prints a `secp256k1_xonly_pubkey`

Usage
-------
- you can call these function from:
    - any file in the `src/` directory (except the files where these `struct` are defined)
    - any module
    - `src/tests.c`

- you cannot call these functions in benchmark files
    - `bench.c` is linked against libsecp256k1 hence, these internal debug funcs won't be available
    - you need to exposed these funcs as `SECP256K1_API` if you want to call these funcs in benchmark