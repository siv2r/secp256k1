#! /bin/bash

# script to compare the runtime for different values of `STRAUSS_MAX_TERMS_PER_BATCH`
# macro used in `secp256k1_batch_create`

# Usage: ./batch_threshold.sh <lower_limit> <upper_limit>

# Example: /batch_threshold.sh 10 15
# Here, 10 is the lower limit and 15 is the upper limit

# replace `schnorrsig_verify` by `tweak_add_check` for batch_verification
# of tweaked pubkey checks
# Note: do not change the order of $1 and $2
./bench $1 $2 schnorrsig_verify | sed '2d;s/ \{1,\}//g' > batch_threshold.csv &

PID=$!
while kill -0 "$PID" >/dev/null 2>&1; do
    echo "Generating CSV file..."
    sleep 60
done
echo "CSV file generation complete!!"
