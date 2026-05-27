# Experiment Background

This repo contains an SD-JWT experiment. The SD-JWT (credential) is produced by a Python script and used by the Noir circuits.

Quick start
1. Install Python dependencies used by the scripts (if needed):

```bash
pip install -r scripts/requirements.txt
```

2. Generate the SD-JWT (from the repository root):

```bash
python3 scripts/1-create-prover.py
```

2. Run the provided pipeline scripts:

```bash
./scripts/2-compile-circuit.sh   # compile Noir circuits
./scripts/3-create-witness.sh    # create witness(s)
./scripts/4-create-proof.sh      # create proofs
```

Notes
- Scripts print timing/stats and place outputs under the project `proofs/` and `target/` folders.
- If a command is missing from your PATH (e.g. `nargo`), source your shell rc or add the tool to PATH before running the scripts.

That's it — the steps above reproduce the SD-JWT generation and the prove/verify pipeline used in the experiment.
