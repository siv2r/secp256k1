#!/usr/bin/env python3
import sys
import os
from collections import defaultdict
import numpy as np
import matplotlib.pyplot as plt
from scipy import stats

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <train_data.csv> <test_data.csv>", file=sys.stderr)
    sys.exit(1)

def load_csv(filename):
    data = defaultdict(list)
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            parts = line.split(',')
            if len(parts) == 3:
                data[parts[0]].append((int(parts[1]), float(parts[2])))
    return data

train_data = load_csv(sys.argv[1])
test_data = load_csv(sys.argv[2])

os.makedirs('diagrams', exist_ok=True)

analysis = []
for algo, train_points in train_data.items():
    train_points.sort()
    ns_train = [p[0] for p in train_points]
    times_train = [p[1] for p in train_points]

    # Fit model on training data
    train_result = stats.linregress(ns_train, times_train)
    slope, intercept = train_result.slope, train_result.intercept

    # Compute metrics on test data
    test_points = test_data.get(algo, [])
    test_points.sort()
    ns_test = [p[0] for p in test_points]
    times_test = [p[1] for p in test_points]
    test_result = stats.linregress(ns_test, times_test)
    r_squared = test_result.rvalue ** 2
    pvalue = test_result.pvalue
    stderr = test_result.stderr

    # Fitted line at test data x-coordinates
    fitted_line = np.array(ns_test) * slope + intercept

    analysis.append((algo, r_squared, stderr, pvalue, slope, intercept))

    plt.figure()
    plt.scatter(ns_test, times_test, c='blue')
    plt.plot(ns_test, fitted_line, 'r-')
    plt.xlabel('Batch size (n)')
    plt.ylabel('Time (μs)')
    plt.title(algo)
    plt.savefig(f'diagrams/{algo}.png')
    plt.close()

with open('diagrams/analysis.md', 'w') as f:
    f.write("# Linear Regression Analysis\n\n")
    f.write("## Metric Definitions\n\n")
    f.write("| Metric | Meaning | Good Value for Benchmarking |\n")
    f.write("|--------|---------|-----------------------------|\n")
    f.write("| R² | How well the linear model fits (0-1) | > 0.95 (strong linear relationship) |\n")
    f.write("| Std Error | Uncertainty in slope estimate | Low relative to slope |\n")
    f.write("| p-value | Probability slope = 0 by chance | < 0.05 (statistically significant) |\n")
    f.write("| Slope | Time increase per additional n (μs) | Positive, algorithm-dependent |\n")
    f.write("| Intercept | Fixed overhead time (μs) | Algorithm-dependent |\n\n")
    f.write("## Per-Algorithm Metrics\n\n")
    f.write("| Algorithm | R² | Std Error | p-value | Slope | Intercept |\n")
    f.write("|-----------|------|-----------|---------|-------|----------|\n")
    for algo, r2, se, pv, sl, ic in analysis:
        f.write(f"| {algo} | {r2:.6f} | {se:.4f} | {pv:.2e} | {sl:.4f} | {ic:.2f} |\n")

print(f"Generated {len(train_data)} diagrams in diagrams/")
print(f"Generated analysis in diagrams/analysis.md")
