# Proof of Concept for Privacy-Preserving e-ID

This repository contains two Proof-of-Concepts (PoC) on
how to implement privacy-preserving algorithms with
electronic identities.
It is funded by the IP-ICT 101.292 Innolink Grant on
**Secure and Privacy-Preserving Credentials
for E-ID**.
You can find more information in the 
[MS2 report](https://github.com/eid-privacy/MS2-Minimal-Viable-Project/releases/download/2026-01-06_12-45/101.292-IP-ICT-ms2-report-2026-01-06_12-45.pdf).

The first PoC is created using the 
[docknetwork/crypto](https://github.com/docknetwork/crypto)
library and is written in Rust.
It uses Bulletproofs and BBS signatures to create the
various proofs for the PoC.

The second PoC uses [noir-lang](https://github.com/noir-lang/noir)
to work on a fixed-size credential.
The Barretenberg backend implements a 
[UltraHONK](https://rknhr-uec.github.io/aztec-protocol-spec/protocol-specs/cryptography/proving-system/overview)
proof which is optimized for blockchains, but still
fast enough for our goals.

# Implemented Proofs

According to our grant, we proposed to implement the following 4
types of proofs:

- WP3 - holder binding: proving that the holder can create a signature
on the challenge sent by the verifier, which can be verified by the
public key stored in the credential
- WP4 - issuer signature: proving that the holder has access to a
credential which has been signed by a publicly known public key
- WP5 - age verification: proving that the credential of the
holder has an `birthdate` field with a date 18 years or more in
the past
- WP6 - non-revocation: proving that the credential of the
holder has an `id` field which has a corresponding `0` bit set
in the revocation list signed by a publicly known key

For more details, please have a look at our [REPORT].

# Running the Examples with DevBox

You can follow the instructions for the [Noir Prover](noir/README.md)
or the [Docknetwork Prover](docknetwork/README.md).
TLDR:

- [Install devbox](https://www.jetify.com/docs/devbox/installing-devbox)
- Run `devbox run noir-all` and `devbox run dock-all` to run
  the examples on your machine

# Running the Examples with Docker

Alternatively, you can use our pre-built Docker image using the Make targets from the root of this repository:

1. To build the image run:
```bash
make build
```
2. To clean the docker image run:
```bash
make clean-image
```

3. To run all docknetwork tests:
```bash
make dock-all
```

4. To run all noir tests:
```bash
make noir-all
```

5. To run all tests:
```bash
make all
```

6. To clean all build artifacts:
```bash
make clean
```

7. To clean only noir build artifacts:
```bash
make noir-clean
```

8. To spawn an interactive shell inside the container:
```bash
make debug-shell
```

# Running the Verifier and Prover as Separate Services with Docker Compose
We also provide a way to run the prover and verifier as separate services using Docker Compose.

1. To start the services run:
```bash
docker-compose up
```
2. To stop the services run:
```bash
docker-compose down
```

You can call the prover service at `http://localhost:8000/prove` with a POST request containing the `circuit` as form data to generate a proof and verify it with the verifier service. (Available circuits: `c03_holder_binding`, `c04_issuer_signature`, `c05_age_verification`, `c06_non_revocation`, `c09_full_proof`).
The endpoint also takes an optional `scheme` parameter to specify the proving scheme to use (e.g., `ultra_honk`, `plonk`, etc.). If not provided, it will use the default scheme specified in the environment variable `DEFAULT_SCHEME`.

For example:
```bash
curl -X POST http://localhost:8000/prove -H "Content-Type: application/x-www-form-urlencoded" -d "circuit=c05_age_verification"
```

You can also directly call the verifier service at `http://localhost:8080/verify` with a POST request containing the `proof`, `vk`, and `public_inputs` as form data to verify a proof. The endpoint also takes an optional `scheme` parameter to specify the proving scheme used for the proof. If not provided, it will use the default scheme specified in the environment variable `DEFAULT_SCHEME`.

For example:
```bash
curl -X POST http://localhost:8080/verify -F "proof=@path/to/proof" -F "vk=@path/to/vk" -F "public_inputs=@path/to/public_inputs"
```

You can run time testing on the prover and verifier services by running:
```bash
make test-remote
```

The results will be stored in `noir/stats_remote_proof_times.csv`.

# Summary of Runtimes

Here is a summary of how long the proofs and verifications take
on a MacBook Pro Apple M2 Max from 2023.
All times are in seconds.

| Docknetwork test              | setup [s] | create_proof [s] | verify [s] | proof_size [B] |
|------------------------------|-------|--------------|--------|------------|
| c03_proof_holder             | 0.197 | 6.622        | 7.921  | 186429     |
| c04_proof_credential         | 0.158 | 0.031        | 0.052  | 570        |
| c05_proof_predicate          | 0.238 | 0.036        | 0.060  | 538        |
| c05_proof_predicate_age      | 0.238 | 0.369        | 0.115  | 1952       |
| c06_proof_non_revocation     | 0.160 | 0.037        | 0.098  | 760        |
| c09_proof_full               | 0.172 | 7.125        | 8.515  | 189141     |

<!-- NOIR_STATS_START -->
<!-- regenerate with: python noir/scripts/update-readme-stats.py -->
| Noir test            | acir  | circuit | create_vk [s] | create_proof [s] | verify [s] | proof_size [B] |
|----------------------|-------|---------|---------------|------------------|------------|----------------|
| c03_holder_binding   | 2108  | 44906   | 0.14          | 0.43             | 0.01       | 14656          |
| c04_issuer_signature | 535   | 59263   | 0.24          | 0.53             | 0.01       | 14656          |
| c05_age_verification | 285   | 3227    | 0.02          | 0.09             | 0.01       | 14656          |
| c06_non_revocation   | 1011  | 56521   | 0.24          | 0.50             | 0.01       | 14656          |
| c09_full_proof       | 3211  | 149211  | 0.49          | 1.20             | 0.01       | 14656          |
| d10_swiyu_jwt        | 92811 | 453007  | 1.29          | 2.77             | 0.01       | 14656          |
<!-- NOIR_STATS_END -->


# Future Work

For the second half of our grant, we will work together with
our partners to get feedback on these PoCs.
If they validate the approach, we will work on improving the
proving system from Noir to tilt the balance away from
long proving time to longer verification time.

# CHANGELOG

- 2026/01/13

Patrick Amrein from Ubique suggested to use `--release` in the `cargo test`
for the docknetwork simulations.
This improved complete proving times for docknetwork by a factor of 15!
Now it is faster in all aspects than noir, which makes more sense.
