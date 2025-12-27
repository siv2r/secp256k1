#!/usr/bin/env python3
import sys
import os
from collections import defaultdict
import matplotlib.pyplot as plt

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <calib_data.csv>", file=sys.stderr)
    sys.exit(1)

data = defaultdict(list)
with open(sys.argv[1], 'r') as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#'): continue
        parts = line.split(',')
        if len(parts) == 3:
            data[parts[0]].append((int(parts[1]), float(parts[2])))

os.makedirs('diagrams', exist_ok=True)

for algo, points in data.items():
    points.sort()
    ns = [p[0] for p in points]
    times = [p[1] for p in points]

    plt.figure()
    plt.plot(ns, times, 'o-')
    plt.xlabel('Batch size (n)')
    plt.ylabel('Time (μs)')
    plt.title(algo)
    plt.savefig(f'diagrams/{algo}.png')
    plt.close()

print(f"Generated {len(data)} diagrams in diagrams/")
