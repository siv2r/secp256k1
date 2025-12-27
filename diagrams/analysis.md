# Linear Regression Analysis

## Metric Definitions

| Metric | Meaning | Good Value for Benchmarking |
|--------|---------|-----------------------------|
| R² | How well the linear model fits (0-1) | > 0.95 (strong linear relationship) |
| Std Error | Uncertainty in slope estimate | Low relative to slope |
| p-value | Probability slope = 0 by chance | < 0.05 (statistically significant) |
| Slope | Time increase per additional n (μs) | Positive, algorithm-dependent |
| Intercept | Fixed overhead time (μs) | Algorithm-dependent |

## Per-Algorithm Metrics

| Algorithm | R² | Std Error | p-value | Slope | Intercept |
|-----------|------|-----------|---------|-------|----------|
| STRAUSS | 0.983536 | 0.1660 | 1.29e-25 | 6.2956 | -1917.23 |
| PIPPENGER_1 | 0.999995 | 0.0039 | 6.29e-73 | 8.5860 | -133.20 |
| PIPPENGER_2 | 0.999992 | 0.0036 | 9.98e-71 | 6.7066 | -115.04 |
| PIPPENGER_3 | 0.999993 | 0.0026 | 8.15e-71 | 4.9746 | -34.11 |
| PIPPENGER_4 | 0.999996 | 0.0015 | 5.34e-75 | 4.1772 | -13.27 |
| PIPPENGER_5 | 0.999995 | 0.0015 | 1.16e-73 | 3.5473 | 56.56 |
| PIPPENGER_6 | 0.999991 | 0.0019 | 2.30e-69 | 3.1035 | 105.03 |
| PIPPENGER_7 | 0.999994 | 0.0013 | 4.69e-72 | 2.7083 | 219.62 |
| PIPPENGER_8 | 0.999989 | 0.0016 | 2.64e-68 | 2.4879 | 414.58 |
| PIPPENGER_9 | 0.999977 | 0.0021 | 3.76e-64 | 2.2872 | 719.46 |
| PIPPENGER_10 | 0.999953 | 0.0028 | 5.02e-60 | 2.1705 | 1287.92 |
| PIPPENGER_11 | 0.999847 | 0.0049 | 4.73e-53 | 2.0592 | 2321.53 |
| PIPPENGER_12 | 0.999583 | 0.0075 | 3.62e-47 | 1.9331 | 4153.43 |
