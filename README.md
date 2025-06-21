# FuzzerBench

FuzzerBench is a Linux kernel module for precision microbenchmarking, adapted from [**nanoBench**](https://github.com/andreas-abel/nanoBench) and designed specifically for fuzzing performance counter behaviors. It allows injecting input groups and test cases at runtime and executes them with fine-grained control over the performance monitoring infrastructure.

The module facilitates efficient benchmarking and fuzzing by exposing a **sysfs** interface for setting test parameters, uploading code, and retrieving results.

---

## Overview

FuzzerBench enables users to:
- Benchmark custom instruction sequences with precise control.
- Supply fuzzed inputs to registers dynamically via `sysfs`.
- Configure performance counters and MSRs.
- Extract cycle-level measurements and trace results after execution.
- Control execution core, measurement mode, and aggregation strategy.

---

## Installation

### Prerequisites
- Linux kernel headers installed.
- Root privileges (for loading kernel modules).
- Kernel compiled with kallsyms and sysfs support.

### Build and Insert

```bash
make
sudo insmod nb_km.ko
