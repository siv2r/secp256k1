#!/usr/bin/env bash

output_file=$1
cur_dir=$(pwd)

cd ../../
echo "HEAD: $(git rev-parse --short HEAD)" > "$cur_dir/$output_file.log"
make clean
./autogen.sh
./configure >> "$cur_dir/$output_file.log"
make -j12
make check -j12 >> "$cur_dir/$output_file.log"
./bench_ecmult calib_discover > "$cur_dir/$output_file"
