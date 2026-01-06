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

# Running the Examples

You can follow the instructions for the [Noir Prover](noir/README.md)
or the [Docknetwork Prover](docknetwork/README.md).
TLDR:

- [Install devbox](https://www.jetify.com/docs/devbox/installing-devbox)
- Run `devbox run noir-all` and `devbox run dock-all` to run
  the examples on your machine

# Summary of Runtimes

Here is a summary of how long the proofs and verifications take
on a MacBook Pro Apple M2 Max from 2023.
All times are in seconds.

| Docknetwork test              | setup [s] | create_proof [s] | verify [s] | proof_size [s] |
|------------------------------|-------|--------------|--------|------------|
| c03_proof_holder             | 0.197 | 6.622        | 7.921  | 186429     |
| c04_proof_credential         | 0.158 | 0.031        | 0.052  | 570        |
| c05_proof_predicate          | 0.238 | 0.036        | 0.060  | 538        |
| c05_proof_predicate_age      | 0.238 | 0.369        | 0.115  | 1952       |
| c06_proof_non_revocation     | 0.160 | 0.037        | 0.098  | 760        |
| c09_proof_full               | 0.172 | 7.125        | 8.515  | 189141     |

| Noir test                    | acir | circuit | create_vk [s] | create_proof [s] | verify [s] | proof_size [s] |
|-----------------------------|------|---------|-----------|--------------|--------|------------|
| c03_holder_binding          | 2108 | 41283   | 0.19      | 0.49         | 0.02   | 16224      |
| c04_issuer_signature        | 535  | 55419   | 0.27      | 0.59         | 0.02   | 16224      |
| c05_age_verification        | 285  | 3208    | 0.04      | 0.12         | 0.02   | 16224      |
| c06_non_revocation          | 1024 | 52764   | 0.24      | 0.51         | 0.02   | 16224      |
| c09_full_proof              | 3224 | 141526  | 0.55      | 1.49         | 0.02   | 16224      |


# Future Work

For the second half of our grant, we will work together with
our partners to get feedback on these PoCs.
If they validate the approach, we will work on improving the
proving system from Noir to tilt the balance away from
long proving time to longer verification time.
