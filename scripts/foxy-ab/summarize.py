#!/usr/bin/env python3
"""Summarize the ferrox-vs-arman A/B legs into a table and a JSON record.

Durations here are measurements, never gates: this prints the ratio and says
which leg carried the bytes, and it does not fail on who won.
"""

import argparse
import json
import statistics
import sys
from collections import defaultdict


def read_legs(path):
    rates = defaultdict(list)
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) != 6:
                raise SystemExit(f"{path}:{number}: want 6 columns, got {line!r}")
            carrier, engine, direction, _round, raw_bytes, raw_seconds = parts
            try:
                size = int(raw_bytes)
                seconds = float(raw_seconds)
            except ValueError as exc:
                raise SystemExit(f"{path}:{number}: {line!r}: {exc}") from exc
            if size > 0 and seconds > 0:
                rates[(carrier, engine, direction)].append(size / seconds)
    return rates


def read_resources(path):
    rows = {}
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) not in (5, 6, 7):
                raise SystemExit(
                    f"{path}:{number}: want 5 to 7 columns, got {line!r}"
                )
            carrier, engine, raw_cpu, raw_rss, edge = parts[:5]
            same_ip = parts[5] if len(parts) >= 6 else "unknown"
            exit_ip = parts[6] if len(parts) == 7 else ""
            try:
                cpu_ms = int(raw_cpu)
                rss_kib = int(raw_rss)
            except ValueError as exc:
                raise SystemExit(f"{path}:{number}: {line!r}: {exc}") from exc
            key = (carrier, engine)
            previous = rows.get(key)
            if previous is None:
                rows[key] = {
                    "cpu_ms": cpu_ms,
                    "peak_rss_kib": rss_kib,
                    "edge": edge,
                    "same_ip": same_ip,
                    "exit_ip": exit_ip,
                }
                continue
            previous["cpu_ms"] += cpu_ms
            previous["peak_rss_kib"] = max(previous["peak_rss_kib"], rss_kib)
            if same_ip != "yes":
                previous["same_ip"] = "no"
            for field, value in (("edge", edge), ("exit_ip", exit_ip)):
                seen = previous[field].split(",") if previous[field] else []
                if value and value not in seen:
                    previous[field] = ",".join(seen + [value])
    return rows


def read_probes(path):
    probes = defaultdict(list)
    try:
        handle = open(path, encoding="utf-8")
    except FileNotFoundError:
        return probes
    with handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) != 7:
                raise SystemExit(f"{path}:{number}: want 7 columns, got {line!r}")
            carrier, engine, _probe, raw_ok, raw_connect, raw_ttfb, raw_total = parts
            try:
                ok = int(raw_ok)
                connect = float(raw_connect)
                ttfb = float(raw_ttfb)
                total = float(raw_total)
            except ValueError as exc:
                raise SystemExit(f"{path}:{number}: {line!r}: {exc}") from exc
            probes[(carrier, engine)].append((ok, connect, ttfb, total))
    return probes


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[int(round((len(ordered) - 1) * q))]


def moved_bytes(path):
    total = defaultdict(int)
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            parts = line.strip().split("\t")
            if len(parts) != 6:
                continue
            carrier, engine, _direction, _round, raw_bytes, _seconds = parts
            try:
                total[(carrier, engine)] += int(raw_bytes)
            except ValueError:
                continue
    return total


def mib(rate):
    return rate / (1 << 20)


def ratio(numerator, denominator):
    if denominator == 0:
        return None
    return numerator / denominator


def fmt(value, digits=2):
    return "n/a" if value is None else f"{value:.{digits}f}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--legs", default="target/foxy-ab/legs.tsv")
    parser.add_argument("--resources", default="target/foxy-ab/resources.tsv")
    parser.add_argument("--probes", default="target/foxy-ab/probes.tsv")
    parser.add_argument("--json", default="target/foxy-ab/summary.json")
    args = parser.parse_args()

    rates = read_legs(args.legs)
    resources = read_resources(args.resources)
    probes = read_probes(args.probes)
    totals = moved_bytes(args.legs)

    carriers = sorted(
        {key[0] for key in rates}
        | {key[0] for key in resources}
        | {key[0] for key in probes}
    )
    directions = ["download", "upload"]
    summary = {"carriers": {}, "note": "durations are measurements, not gates"}

    lines = []
    lines.append("### Foxy lane A/B, ferrox vs arman (same pass, same edge and edge IP)")
    lines.append("")
    lines.append("| carrier | direction | ferrox MiB/s | arman MiB/s | ferrox / arman | rounds |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for carrier in carriers:
        cell = {}
        for direction in directions:
            ferrox = rates.get((carrier, "ferrox", direction), [])
            arman = rates.get((carrier, "arman", direction), [])
            f_med = statistics.median(ferrox) if ferrox else None
            a_med = statistics.median(arman) if arman else None
            cell[direction] = {
                "ferrox_mib_s": None if f_med is None else mib(f_med),
                "arman_mib_s": None if a_med is None else mib(a_med),
                "ferrox_over_arman": None
                if f_med is None or a_med is None
                else ratio(f_med, a_med),
                "rounds": [len(ferrox), len(arman)],
            }
            lines.append(
                f"| {carrier} | {direction} | "
                f"{fmt(None if f_med is None else mib(f_med))} | "
                f"{fmt(None if a_med is None else mib(a_med))} | "
                f"{fmt(cell[direction]['ferrox_over_arman'], 3)} | "
                f"{len(ferrox)}/{len(arman)} |"
            )
        summary["carriers"][carrier] = cell

    lines.append("")
    lines.append(
        "| carrier | engine | CPU ms | CPU ms/MiB | peak RSS KiB | same IP | exit IP | edge |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for carrier in carriers:
        for engine in ("ferrox", "arman"):
            row = resources.get((carrier, engine))
            if row is None:
                continue
            total = totals.get((carrier, engine), 0)
            per_mib = None if total == 0 else row["cpu_ms"] / (total / (1 << 20))
            summary["carriers"].setdefault(carrier, {}).setdefault("resources", {})[
                engine
            ] = {
                "cpu_ms": row["cpu_ms"],
                "cpu_ms_per_mib": per_mib,
                "peak_rss_kib": row["peak_rss_kib"],
                "same_ip": row["same_ip"],
                "exit_ip": row["exit_ip"],
                "edge": row["edge"],
            }
            exit_ip = f"`{row['exit_ip']}`" if row["exit_ip"] else ""
            lines.append(
                f"| {carrier} | {engine} | {row['cpu_ms']} | {fmt(per_mib, 3)} | "
                f"{row['peak_rss_kib']} | {row['same_ip']} | {exit_ip} | `{row['edge']}` |"
            )

    if any(
        row["same_ip"] == "no"
        for row in resources.values()
    ):
        lines.append("")
        lines.append(
            "`same IP = no` means both engines dialed the same edge and edge IP, "
            "but the provider gave each session its own egress address: the server "
            "is the same, the exit IP is per session."
        )

    if probes:
        lines.append("")
        lines.append(
            "| carrier | engine | probes | loss % | median TTFB ms | p95 TTFB ms | jitter ms |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for carrier in carriers:
            for engine in ("ferrox", "arman"):
                rows = probes.get((carrier, engine))
                if not rows:
                    continue
                n = len(rows)
                lost = sum(1 for ok, *_ in rows if ok == 0)
                ttfb = [t for ok, _c, t, _total in rows if ok and t > 0]
                median = statistics.median(ttfb) if ttfb else None
                p95 = percentile(ttfb, 0.95)
                if len(ttfb) > 1:
                    jitter = statistics.pstdev(ttfb)
                elif ttfb:
                    jitter = 0.0
                else:
                    jitter = None
                loss_pct = 100.0 * lost / n
                summary["carriers"].setdefault(carrier, {}).setdefault("probes", {})[
                    engine
                ] = {
                    "probes": n,
                    "loss_pct": loss_pct,
                    "median_ttfb_ms": None if median is None else median * 1000,
                    "p95_ttfb_ms": None if p95 is None else p95 * 1000,
                    "jitter_ms": None if jitter is None else jitter * 1000,
                }
                lines.append(
                    f"| {carrier} | {engine} | {n} | {fmt(loss_pct, 1)} | "
                    f"{fmt(None if median is None else median * 1000, 1)} | "
                    f"{fmt(None if p95 is None else p95 * 1000, 1)} | "
                    f"{fmt(None if jitter is None else jitter * 1000, 1)} |"
                )
        for carrier in carriers:
            cell = summary["carriers"][carrier]
            res = cell.get("probes", {})
            f = res.get("ferrox")
            a = res.get("arman")
            if f and a:
                f_med = f.get("median_ttfb_ms")
                a_med = a.get("median_ttfb_ms")
                if f_med and a_med:
                    cell["ferrox_ttfb_over_arman"] = ratio(f_med, a_med)
                cell["ferrox_loss_pp_minus_arman"] = f["loss_pct"] - a["loss_pct"]
        lines.append("")
        lines.append(
            "TTFB is the time from the probe to the first response byte through the "
            "tunnel; loss is a probe that timed out or reset at this layer, not a "
            "kernel packet counter. Lower TTFB, lower loss and lower jitter are better."
        )

    for carrier in carriers:
        cell = summary["carriers"][carrier]
        res = cell.get("resources", {})
        ferrox = res.get("ferrox")
        arman = res.get("arman")
        if ferrox and arman:
            f_per_mib = ferrox.get("cpu_ms_per_mib")
            a_per_mib = arman.get("cpu_ms_per_mib")
            if f_per_mib and a_per_mib:
                cell["arman_cpu_per_mib_over_ferrox"] = ratio(a_per_mib, f_per_mib)
            cell["ferrox_rss_over_arman"] = ratio(
                ferrox["peak_rss_kib"], arman["peak_rss_kib"]
            )

    lines.append("")
    lines.append(
        "A throughput ratio above 1.0 is ferrox faster on that cell; a CPU-per-MiB "
        "ratio above 1.0 is ferrox cheaper per byte; an RSS ratio below 1.0 is "
        "ferrox smaller. Nothing here gates a build: the byte counts gate, the "
        "durations are read."
    )

    text = "\n".join(lines) + "\n"
    with open(args.json, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
