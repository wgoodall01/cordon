#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." >/dev/null 2>&1 && pwd )"
cd "$DIR"

# Build the code
cargo build --release --example fully_sandboxed_echo
cargo build --release --example non_sandboxed_echo
cargo build --release --example std_echostd_echo

# Benchmark vs. docker
hyperfine \
	--prepare 'sleep 0.1' \
	'./target/release/examples/std_echo' \
	'./target/release/examples/non_sandboxed_echo' \
	'./target/release/examples/fully_sandboxed_echo' \
	'docker run busybox sh -c "echo Hello, World!"' \
