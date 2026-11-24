#!/usr/bin/env bash
# Gate de cadeia de suprimentos (G0): licenças/fontes, vulnerabilidades e SBOM por release.
# Requer: cargo install --locked cargo-deny cargo-audit cargo-cyclonedx
set -euo pipefail
cd "$(dirname "$0")/.."
cargo deny check
cargo audit
cargo cyclonedx --format json --spec-version 1.5
