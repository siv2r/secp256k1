echo "Running ecmult benchmarks..."
sleep 5
./bench_ecmult calib > calib_data_train.csv
sleep 5
./bench_ecmult calib > calib_data_test.csv
echo "Generating benchmark graphs..."
python3 tools/ecmult_multi_analyze.py calib_data_train.csv calib_data_test.csv
echo "Calibrating C, D values..."
python3 tools/ecmult_multi_calib.py calib_data_train.csv