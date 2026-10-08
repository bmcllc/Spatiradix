# Reference measurement context

These files were measured on 2026-10-07 in a release build on Linux x86_64, using an Intel Core i5-11260H and 12 available logical CPUs. The workload is a trained linear softmax model with four actions, three `f64` features and all actions available. Each report contains 1,000 warmup evaluations followed by 10,000 individually timed evaluations.

The initial measurements were generated with a temporary standalone Cargo harness while the full crate's Economy module was being integrated. The harness used the same runtime, trainer, benchmark and example source, with the repository's existing dependencies and lockfile. It did not run the Economy service. The complete integrated example can be run from the repository root with:

```sh
cargo run --release -p mycelium-s1 --example train_and_benchmark -- /tmp/mycelium-s1-report
```

The inference report measures dimension and mask validation, allocation and masked softmax. The metered report adds Ed25519 verification on every evaluation and an in-memory quota counter; its 11,000 consumed evaluations include warmup. It does not measure durable counters, checkout, GPU execution, networking or an embedded game frame. CPU affinity, frequency and background processes were not controlled. These measurements describe this machine and workload, and are not a production latency guarantee.

The example training data is hand-labelled and synthetic: 20 training observations and 12 independent validation observations. The observed loss reduction and validation accuracy verify the training implementation on this dataset; gameplay quality requires independent data from the studio.
