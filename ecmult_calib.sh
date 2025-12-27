echo "Running ecmult benchmarks..."
./bench_ecmult calib > calib_data.csv
echo "Generating benchmark graphs..."
python3 tools/ecmult_multi_analyze.py calib_data.csv
echo "Calibrating C, D values..."
python3 tools/ecmult_multi_calib.py calib_data.csv