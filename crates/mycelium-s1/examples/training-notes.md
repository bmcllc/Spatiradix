# Supervised model training and native benchmarks

`npc-training.json` contains 20 hand-labelled synthetic observations and 12 independent synthetic validation observations. Health and ammo are centered around zero; pressure varies but does not determine these illustrative labels. This dataset exercises the optimizer and serialization. Its accuracy does not establish quality on real gameplay.

The runtime model is a linear classifier with masked softmax probabilities. The trainer performs deterministic full-batch gradient descent on cross-entropy, with L2 weight regularization. Features must already be normalized consistently by the application; the trainer neither invents labels nor learns a nonlinear decision boundary. Validation observations are measured before and after training and never used by the optimizer. Fine-tuning accepts an existing artifact with the same ordered actions and feature dimensions.

The current runtime artifact stores weights, bias and action names, but not feature names. Keep the ordered feature schema from the training report alongside the artifact and use that order in every inference or fine-tuning dataset. Matching dimensions alone cannot detect a semantic feature reordering.

Training is intended for the local developer CLI. Input validation checks dimensions, masks, labels and finite numbers, but the individual size limits still permit expensive workloads when combined. A public synchronous service must add an aggregate compute and memory budget before accepting untrusted datasets or configurations.

Run the complete reproducible native example from the repository root:

```sh
cargo run --release -p mycelium-s1 --example train_and_benchmark -- /tmp/mycelium-s1-report
```

It writes a runtime-compatible model, a training report, an inference benchmark, and a metered benchmark. Each benchmark performs 1,000 warmup calls and measures 10,000 individual calls using `Instant`. Percentiles use nearest rank. Per-call timer overhead, validation and allocation are included. The report records build optimization, OS, architecture, CPU and dimensions. Results depend on this workload and machine; they are not a frame-time guarantee.

The metered measurement additionally verifies an Ed25519 ticket and advances an in-memory quota counter on every evaluation, including warmup. The sample ticket is created with a public deterministic key exclusively for the benchmark. Filesystem counter persistence, online checkout, networking, GPU execution and game integration are outside these measurements. A production key or a player's credit allocation must not be supplied to the synthetic benchmark.
