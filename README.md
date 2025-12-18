# Proof of Concept for Privacy-Preserving e-ID

This repository contains two Proof-of-Concepts (PoC) on
how to implement privacy-preserving algorithms with
electronic identities.
It is funded by the IP-ICT 101.292 Innolink Grant on
**Secure and Privacy-Preserving Credentials
for E-ID**.

The first PoC is created using the 
[docknetwork/crypto](https://github.com/docknetwork/crypto)
library and is written in Rust.
It uses Bulletproofs and BBS signatures to create the
various proofs for the PoC.

The second PoC uses [noir-lang](https://github.com/noir-lang/noir)
to work on a fixed-size credential.
The Barretenberg backend implements a **hyper-Plonk**
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
on a MacBook Pro Apple M2 Max from 2023:

# Future Work

For the second half of our grant, we will work together with
our partners to get feedback on these PoCs.
If they validate the approach, we will work on improving the
proving system from Noir to tilt the balance away from
long proving time to longer verification time.
