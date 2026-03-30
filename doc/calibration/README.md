# ABCD Calibration Range Discovery

Empirically discovers optimal calibration ranges for ecmult_multi's ABCD
cost model. This replaces hand-picked ranges with data-driven ones.

## Background

The ABCD cost model uses `time/n = C + D/n` to select between Strauss and
Pippenger algorithms. C and D are fitted via linear regression on benchmark
data. The fit quality depends on which batch sizes are included — fitting
Strauss on n=2-500 when it's only optimal for n=2-85 can skew the results.

This pipeline measures all 14 algorithms at all batch sizes without filtering,
then uses empirical data to find where each algorithm is actually fastest.

## Usage

### Full pipeline

```
make
```

This will:
1. Build secp256k1 and run `bench_ecmult calib_discover` (slow — measures
   14 algorithms × ~55 batch sizes)
2. Run `discover_ranges.py` to find optimal ranges and generate data files
3. Run gnuplot to produce graphs

### Step by step

```bash
# 1. Run the benchmark (from project root)
./bench_ecmult calib_discover > doc/calibration/raw_data.csv

# 2. Analyze results
cd doc/calibration
python3 discover_ranges.py < raw_data.csv

# 3. Generate graphs
gnuplot plot.gp
```

### Output

- `ranges_table.md` — Optimal ranges table with per-point times and speedups
- `optimal_ranges.json` — Machine-readable ranges
- `per_point_time.png` — Per-point time for all 14 algorithms
- `speedup_vs_individual.png` — Speedup over individual ecmult
- `*.dat` — Per-algorithm data files

### Applying results

Use the ranges from `optimal_ranges.json` to update `bench_ecmult.c`:

- `STRAUSS_MAX_CALIB_BATCH` — set to the max of STRAUSS's optimal range
- `pippenger_min_calib_batch[w]` — set to the min of PIPPENGER_w's range
- `pippenger_max_calib_batch[w]` — set to the max of PIPPENGER_w's range

Then re-run the standard calibration:

```bash
./bench_ecmult calib 2>&1 | python3 tools/ecmult_multi_calib.py
```
