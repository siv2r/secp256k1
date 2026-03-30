#!/usr/bin/env python3
"""
Analyze calib_discover output to find optimal algorithm ranges.

Usage:
    ./bench_ecmult calib_discover 2>&1 | python3 doc/calibration/discover_ranges.py

Reads CSV lines of format: ALGO,N,TIME_US
Outputs:
  - Optimal ranges table (stdout + ranges_table.md)
  - Per-algorithm .dat files for gnuplot
  - optimal_ranges.json
"""
import sys
import json
from collections import defaultdict

def parse_input():
    """Parse CSV input into {algo: [(n, time_us), ...]} and individual baseline."""
    data = defaultdict(list)
    individual = {}
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(',')
        if len(parts) != 3:
            continue
        algo, n_str, time_str = parts
        n = int(n_str)
        time_us = float(time_str)
        if algo == 'INDIVIDUAL':
            individual[n] = time_us
        else:
            data[algo].append((n, time_us))
    return data, individual

def find_winners(data, individual):
    """At each batch size, find which algorithm has lowest per-point time."""
    all_ns = sorted(set(n for pts in data.values() for n, _ in pts))

    lookup = {}
    for algo, pts in data.items():
        lookup[algo] = {n: t for n, t in pts}

    algos = sorted(data.keys(), key=lambda a: algo_sort_key(a))

    results = []
    for n in all_ns:
        best_algo = None
        best_time_per_point = float('inf')

        for algo in algos:
            if n not in lookup[algo]:
                continue
            tpp = lookup[algo][n] / n
            if tpp < best_time_per_point:
                best_time_per_point = tpp
                best_algo = algo

        speedup = None
        if n in individual and best_time_per_point > 0:
            individual_tpp = individual[n] / n
            speedup = individual_tpp / best_time_per_point

        results.append({
            'n': n,
            'best_algo': best_algo,
            'best_tpp': best_time_per_point,
            'speedup': speedup,
        })

    return results, all_ns, algos, lookup

def algo_sort_key(name):
    """Sort order: TRIVIAL=0, STRAUSS=1, PIPPENGER_1=2, ..., PIPPENGER_12=13."""
    if name == 'TRIVIAL':
        return 0
    if name == 'STRAUSS':
        return 1
    if name.startswith('PIPPENGER_'):
        return 1 + int(name.split('_')[1])
    return 100

def derive_ranges(results):
    """Group consecutive batch sizes where the same algorithm wins."""
    if not results:
        return []

    ranges = []
    current_algo = results[0]['best_algo']
    range_start = results[0]['n']
    range_tpps = [results[0]['best_tpp']]
    range_speedups = [results[0]['speedup']]

    for r in results[1:]:
        if r['best_algo'] == current_algo:
            range_tpps.append(r['best_tpp'])
            range_speedups.append(r['speedup'])
        else:
            ranges.append({
                'algo': current_algo,
                'min_n': range_start,
                'max_n': results[results.index(r) - 1]['n'],
                'min_tpp': min(range_tpps),
                'max_tpp': max(range_tpps),
                'min_speedup': min(s for s in range_speedups if s is not None) if any(s is not None for s in range_speedups) else None,
                'max_speedup': max(s for s in range_speedups if s is not None) if any(s is not None for s in range_speedups) else None,
            })
            current_algo = r['best_algo']
            range_start = r['n']
            range_tpps = [r['best_tpp']]
            range_speedups = [r['speedup']]

    ranges.append({
        'algo': current_algo,
        'min_n': range_start,
        'max_n': results[-1]['n'],
        'min_tpp': min(range_tpps),
        'max_tpp': max(range_tpps),
        'min_speedup': min(s for s in range_speedups if s is not None) if any(s is not None for s in range_speedups) else None,
        'max_speedup': max(s for s in range_speedups if s is not None) if any(s is not None for s in range_speedups) else None,
    })

    merged = []
    for rng in ranges:
        if merged and rng['min_n'] == rng['max_n'] and len(ranges) > 2:
            merged[-1]['max_n'] = rng['max_n']
            merged[-1]['min_tpp'] = min(merged[-1]['min_tpp'], rng['min_tpp'])
            merged[-1]['max_tpp'] = max(merged[-1]['max_tpp'], rng['max_tpp'])
            if merged[-1]['min_speedup'] is not None and rng['min_speedup'] is not None:
                merged[-1]['min_speedup'] = min(merged[-1]['min_speedup'], rng['min_speedup'])
                merged[-1]['max_speedup'] = max(merged[-1]['max_speedup'], rng['max_speedup'])
        else:
            merged.append(rng)

    return merged

def write_dat_files(all_ns, algos, lookup, individual):
    """Write per-algorithm .dat files for gnuplot."""
    for algo in algos:
        filename = algo.lower() + '.dat'
        with open(filename, 'w') as f:
            f.write("# N  TIME_PER_POINT_US  SPEEDUP\n")
            algo_data = lookup.get(algo, {})
            for n in all_ns:
                if n not in algo_data:
                    continue
                tpp = algo_data[n] / n
                speedup = ''
                if n in individual and tpp > 0:
                    speedup = '%.4f' % (individual[n] / n / tpp)
                f.write("%d  %.4f  %s\n" % (n, tpp, speedup))

# Algo name -> gnuplot line style index (must match plot.gp)
ALGO_LS = {
    'TRIVIAL': 1, 'STRAUSS': 2,
    'PIPPENGER_1': 3, 'PIPPENGER_2': 4, 'PIPPENGER_3': 5,
    'PIPPENGER_4': 6, 'PIPPENGER_5': 7, 'PIPPENGER_6': 8,
    'PIPPENGER_7': 9, 'PIPPENGER_8': 10, 'PIPPENGER_9': 11,
    'PIPPENGER_10': 12, 'PIPPENGER_11': 13, 'PIPPENGER_12': 14,
}

def short_name(algo):
    """Shorten algorithm name for graph labels."""
    if algo == 'STRAUSS':
        return 'STR'
    if algo.startswith('PIPPENGER_'):
        return 'P' + algo.split('_')[1]
    return algo

def write_crossover_annotations(ranges):
    """Write gnuplot commands for crossover vertical lines and labels."""
    with open('crossover_annotations.gp', 'w') as f:
        f.write("# Auto-generated crossover annotations\n")
        f.write("# Sourced by plot.gp for the winner-only graph\n\n")
        for i in range(1, len(ranges)):
            prev = ranges[i - 1]
            curr = ranges[i]
            # Crossover point is between prev max_n and curr min_n
            x = (prev['max_n'] + curr['min_n']) / 2.0
            label = "%s->%s" % (short_name(prev['algo']), short_name(curr['algo']))
            f.write("set arrow from %.1f, graph 0 to %.1f, graph 1 nohead "
                    "lt rgb \"#AAAAAA\" lw 1 dt 3\n" % (x, x))
            f.write("set label \"%s\" at %.1f, graph 0.95 center font \",8\" "
                    "tc rgb \"#666666\"\n" % (label, x))

def write_winner_segments(ranges, lookup, individual):
    """Write per-range dat files containing only the winning segment's data."""
    for i, rng in enumerate(ranges):
        algo = rng['algo']
        algo_data = lookup.get(algo, {})
        filename = 'winner_%d_%s.dat' % (i, algo.lower())
        with open(filename, 'w') as f:
            f.write("# N  SPEEDUP  (winner segment: %s [%d, %d])\n" %
                    (algo, rng['min_n'], rng['max_n']))
            for n in sorted(algo_data.keys()):
                if n < rng['min_n'] or n > rng['max_n']:
                    continue
                tpp = algo_data[n] / n
                if n in individual and tpp > 0:
                    speedup = (individual[n] / n) / tpp
                    f.write("%d  %.4f\n" % (n, speedup))

def write_winners_plot_commands(ranges):
    """Write gnuplot plot command for winner-only speedup graph."""
    with open('winners_plot.gp', 'w') as f:
        f.write("# Auto-generated plot command for winner-only graph\n")
        f.write("# Each segment shows only the range where that algorithm wins\n\n")
        lines = []
        for i, rng in enumerate(ranges):
            algo = rng['algo']
            dat = 'winner_%d_%s.dat' % (i, algo.lower())
            ls = ALGO_LS.get(algo, 1)
            title = algo.replace('_', '\\\\_')
            lines.append('    "%s" using 1:2 with linespoints title "%s" ls %d' %
                         (dat, title, ls))
        f.write("plot \\\n" + ", \\\n".join(lines) + "\n")

def generate_findings(ranges, algos, results):
    """Generate auto-summary of interesting observations."""
    findings = []

    # 1. Which algorithms are never optimal
    winner_set = set(rng['algo'] for rng in ranges)
    never_optimal = [a for a in algos if a not in winner_set and a != 'TRIVIAL']
    if never_optimal:
        names = ', '.join(never_optimal)
        findings.append("**Never optimal:** %s — dominated by neighbors at every "
                        "batch size." % names)

    # 2. Crossover points
    crossovers = []
    for i in range(1, len(ranges)):
        prev = ranges[i - 1]
        curr = ranges[i]
        mid = (prev['max_n'] + curr['min_n']) // 2
        crossovers.append("%s -> %s at n~%d" % (prev['algo'], curr['algo'], mid))
    if crossovers:
        findings.append("**Crossover points:** " + "; ".join(crossovers) + ".")

    # 3. Max speedup
    best = max(results, key=lambda r: r['speedup'] if r['speedup'] else 0)
    if best['speedup']:
        findings.append("**Peak speedup:** %.2fx at n=%d (%s)." %
                        (best['speedup'], best['n'], best['best_algo']))

    # 4. Strauss range vs current code
    for rng in ranges:
        if rng['algo'] == 'STRAUSS':
            findings.append("**Strauss optimal range:** n=[%d, %d]. Current "
                            "STRAUSS_MAX_CALIB_BATCH=500 may be too wide."
                            % (rng['min_n'], rng['max_n']))
            break

    # 5. Number of useful algorithms
    findings.append("**Useful algorithms:** %d out of 14 are optimal at some "
                    "batch size." % len(winner_set))

    return findings

def format_table(ranges):
    """Format ranges as a markdown table."""
    lines = []
    lines.append("| Optimal Range | Best Algorithm | Per-Point Time (us) | Speedup vs Individual |")
    lines.append("|---------------|----------------|---------------------|-----------------------|")
    for rng in ranges:
        range_str = "[%d, %d]" % (rng['min_n'], rng['max_n'])
        tpp_str = "%.2f - %.2f" % (rng['min_tpp'], rng['max_tpp'])
        if rng['min_speedup'] is not None:
            speedup_str = "%.2fx - %.2fx" % (rng['min_speedup'], rng['max_speedup'])
        else:
            speedup_str = "N/A"
        lines.append("| %-13s | %-14s | %-19s | %-21s |" % (
            range_str, rng['algo'], tpp_str, speedup_str))
    return '\n'.join(lines)

def main():
    data, individual = parse_input()
    if not data:
        print("Error: no data parsed from input", file=sys.stderr)
        sys.exit(1)

    results, all_ns, algos, lookup = find_winners(data, individual)
    ranges = derive_ranges(results)
    findings = generate_findings(ranges, algos, results)

    table = format_table(ranges)
    print("\n" + table + "\n")

    # Print findings to stdout
    if findings:
        print("## Key Findings\n")
        for f_item in findings:
            print("- " + f_item)
        print()

    with open('ranges_table.md', 'w') as f:
        f.write("# Optimal Algorithm Ranges\n\n")
        f.write("Generated by `discover_ranges.py` from `bench_ecmult calib_discover` output.\n\n")
        f.write(table + "\n\n")

        # Key findings section
        if findings:
            f.write("## Key Findings\n\n")
            for f_item in findings:
                f.write("- " + f_item + "\n")
            f.write("\n")

        f.write("## Winner at each batch size\n\n")
        f.write("| N | Best Algorithm | Per-Point Time (us) | Speedup |\n")
        f.write("|---|----------------|---------------------|---------|\n")
        for r in results:
            speedup_str = "%.2fx" % r['speedup'] if r['speedup'] else "N/A"
            f.write("| %d | %s | %.2f | %s |\n" % (r['n'], r['best_algo'], r['best_tpp'], speedup_str))

    write_dat_files(all_ns, algos, lookup, individual)

    # Write gnuplot files for winner-only graph
    write_crossover_annotations(ranges)
    write_winner_segments(ranges, lookup, individual)
    write_winners_plot_commands(ranges)

    ranges_json = {}
    for rng in ranges:
        ranges_json[rng['algo']] = {'min': rng['min_n'], 'max': rng['max_n']}
    with open('optimal_ranges.json', 'w') as f:
        json.dump(ranges_json, f, indent=2)
        f.write('\n')

    print("Written: ranges_table.md, optimal_ranges.json, crossover_annotations.gp, winners_plot.gp, and .dat files")

if __name__ == '__main__':
    main()
