#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." >/dev/null 2>&1 && pwd )"
cd "$DIR"

# Build the code
cargo build --release --example sysbench

# Benchmark vs. docker
echo
echo "--- Sysbench inside container"
./target/release/examples/sysbench


echo
echo "--- Sysbench outside container"
sysbench --test=cpu --num-threads=8 run
