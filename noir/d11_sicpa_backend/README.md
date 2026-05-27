# Experiment Background

This repo contains an SD-JWT experiment. The SD-JWT (credential) is produced by a Python script and consumed by the Noir circuits.

Quick start

1) Recommended — use Devbox (gets correct toolchain):

```bash
devbox shell
# inside devbox:
python3 scripts/1-create-prover.py
./scripts/2-compile-circuit.sh
./scripts/3-create-witness.sh
./scripts/4-create-proof.sh
```


Notes
- Scripts produce timing/stats and place outputs under `proofs/` and `target/`.
- If a CLI tool (e.g. `nargo`, `bb`) is missing, either run inside Devbox or add it to your PATH.

These steps reproduce SD-JWT generation and the prove/verify pipeline used in the experiment.
