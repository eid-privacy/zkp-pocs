# Experiment Background

This repo contains an SD-JWT experiment. The SD-JWT (credential) is produced by a Python script and consumed by the Noir circuits.
The script `create-prover.py` sets up the specific credential structure used in the
SICPA backend, which includes the public key of the issuer in the SD-JWT header.
This is different from the Swiyu-SD-JWT, which has a generic header, and a Web3-DID
in the body of the SD-JWT.
If you have devbox installed, you can create a new SD-JWT which will be written
to Prover.toml:

```bash
devbox shell
# inside devbox:
python3 create-prover.py
```

Once the Prover.toml is written, you can use the scripts from the `zkp-pocs/noir/scripts`
directory to run all benchmarks.

# Notes

If a CLI tool (e.g. `nargo`, `bb`) is missing, either run inside Devbox or add it to your PATH.
