# Proof of Concept for Device/Holder Binding

This directory contains a PoC for the device binding, written in Noir.
Once you installed [devbox](https://www.jetify.com/docs/devbox/installing-devbox/index),
you can run the experiment with the following command:

```bash
devbox run experiment
```

It will output the time and size of the proof created.

## Formats used

For this first PoC, we chose the following formats:

- Credential: a fixed-size credential, where every attribute has a fixed
size, but can be 0-padded
- Signatures: both the issuer and the device signature are done using
ECDSA over P-256

## ZKP Inputs

The `main` function of our ZKP has the following inputs:

- Secret (only known to the holder):
  - `credential`
  - `revocation list` with the start-ID, time of signature, bit-list of revoked credentials,
  and signature from issuer
- Public (known to the holder and the verifier):
  - `public key` of the issuer
  - `current date` in seconds since epoch
- Calculated in the circuit
  - `cred_id` from the `credential`, which is a unique ID of the credential
  - `start`, `revocations`, `time of signature`, `signature`, `list_hash` from the `revocation list`
- Proof
  - the `cred_id` is in the range `start..start + REVOCATION_LIST_LEN`
  - the corresponding bit-entry of the `cred_id` in the `revocations` is 0 (non-revoked)
  - the `time of signature` is not more than 7 days before the `current date`
  - the `signature` can be verified using the `public key` and matches the
    `list_hash`
