#! /bin/bash

# script to compare the runtime for different values of `STRAUSS_MAX_TERMS_PER_BATCH`
# macro used in `secp256k1_batch_create`

# Usage: ./batch_threshold.sh <lower_limit> <upper_limit>

# Example: /batch_threshold.sh 10 15
# Here, 10 is the lower limit and 15 is the upper limit

# replace `schnorrsig_verify` by `tweak_add_check` for batch_verification
# of tweaked pubkey checks
./bench $1 $2 schnorrsig_verify | sed '2d;s/ \{1,\}//g' > batch_threshold.csv
