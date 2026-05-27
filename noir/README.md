# Proof of Concept for Device/Holder Binding

This directory contains a PoC for the device binding, written in Noir.
Once you installed [devbox](https://www.jetify.com/docs/devbox/installing-devbox/index),
you can run the experiment with the following command:

```bash
devbox run noir-all
```

It will output the time and size of the proofs created in the file
`stats.csv`.

# Formats used

For this first PoC, we chose the following formats:

- Credential: a fixed-size credential, where every attribute has a fixed
  size, but can be 0-padded
- Signatures: both the issuer and the device signature are done using
  ECDSA over secp256r1

# Inputs and Proofs created

## WP3 - Holder Binding

The `main` function of our ZKP has the following inputs:

- Secret (only known to the holder, as they would make the presentation linkable):
  - `credential` string
  - `SE signature` over the verifier challenge
- Public (known to the holder and the verifier):
  - `challenge_hash` from the verifier
- Calculated in the circuit
  - `public key` from the `credential`
- Proof
  - the `SE signature` can be verified using the `public key` to match the `challenge_hash`

## WP4 - Issuer Signature

The `main` function of our ZKP has the following inputs:

- Secret (only known to the holder, as they would make the presentation linkable):
  - `credential` string
  - `issuer signature` over the credential
- Public (known to the holder and the verifier):
  - `public key` of the issuer
- Calculated in the circuit
  - `credential_hash` as a sha256 of the credential
- Proof
  - the `issuer signature` can be verified with the `public key` and the `credential_hash`

## WP5 - Age Verification

We chose to prove the favorite predicates of all: age verification.
The `main` function of our ZKP has the following inputs:

- Secret (only known to the holder, as they would make the presentation linkable):
  - `credential` string
- Public (known to the holder and the verifier):
  - `current date`
- Calculated in the circuit
  - `date of birth` from the `credential`
- Proof
  - the `date of birth` is 18 years or more before the `current date`

## WP6 - Non-Revocation

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

## WP9 - Full Proof

The `c09_full_proof` circuit combines all of the individual proofs above
(holder binding, issuer signature, age verification, non-revocation) into
a single ZKP. This is closer to a real-world presentation, where the
verifier wants to check several properties of the credential at once.

The `main` function of our ZKP has the following inputs:

- Secret (only known to the holder):
  - `credential` string
  - `revocation list` with start-ID, time of signature, bit-list of revoked
    credentials, and signature from issuer
  - `device signature` over the verifier challenge
  - `issuer signature` over the credential
- Public (known to the holder and the verifier):
  - `challenge_hash` from the verifier
  - `current date` in seconds since epoch
  - `public key` of the issuer (X and Y coordinates)
- Calculated in the circuit
  - `device public key` extracted from the `credential`
  - `credential_hash` as a sha256 of the credential
  - `date of birth` from the `credential`
  - `cred_id` from the `credential`
  - `revocation_hash` as a sha256 of the revocation list
- Proof
  - the `device signature` is valid over the `challenge_hash` under the
    device public key from the credential
  - the `issuer signature` is valid over the `credential_hash` under the
    issuer's public key
  - the `date of birth` is at least 18 years before the `current date`
  - the `cred_id` is contained in the revocation list and its bit is 0
  - the revocation list is fresh (within the validity period) and the
    issuer's signature on `revocation_hash` is valid

## Demo-10 - Swiyu SD-JWT

Unlike the previous work packages (WP3-WP9), which prove properties of
a custom fixed-size credential, `Demo-10` and `Demo-11` are not formal
work packages but experimental demos that exercise the same ideas on
real-world SD-JWT credentials.

The `d10_swiyu_jwt` circuit applies the same ideas to an actual SD-JWT
credential obtained from the Swiyu E-ID demo issuer. Instead of the
fixed-size custom credential format used in the previous experiments,
this one works directly on the base64url-encoded JWT payload, performs
selective disclosure of the date of birth, and uses ECDSA over the
NIST P-256 curve (secp256r1) — as required by the JWT and the device
binding `cnf` claim. See [`d10_swiyu_jwt/README.md`](./d10_swiyu_jwt/README.md)
for how the SD-JWT was obtained and re-signed for the experiment.

The `main` function of our ZKP has the following inputs:

- Secret (only known to the holder):
  - `payload` — the raw JWT payload (JSON) as a bounded byte vector
  - `jwt_signature` — issuer ES256 signature over `header.payload`
  - `dob_salt`, `dob_value` — salt and value of the SD-JWT `birth_date`
    disclosure
  - `dob_sd_offset` — offset of the DOB digest in the `_sd` array of
    the payload
  - `x_offset`, `y_offset` — offsets of the device public-key X/Y
    coordinates in the `cnf` claim of the payload
  - `device_signature` — ES256 signature over the verifier challenge
- Public (known to the holder and the verifier):
  - `issuer_pub_x`, `issuer_pub_y` — issuer's P-256 public key
  - `now_date` — current date in `YYYYMMDD` form
  - `challenge_nonce` — 32-byte challenge from the verifier
- Calculated in the circuit
  - the base64url-encoded `header.payload` signing input
  - the base64url-encoded SD-JWT disclosure for `birth_date` and its
    sha256 digest
  - the device public key, base64url-decoded from the `cnf` claim
- Proof
  - the `jwt_signature` is a valid ES256 signature by the issuer over
    `header.payload`
  - the salted disclosure for `birth_date` hashes to the digest stored
    at `dob_sd_offset` in the payload's `_sd` array
  - the `dob_value` corresponds to an age of at least 25 years at
    `now_date`
  - the `device_signature` is a valid ES256 signature over the
    `challenge_nonce` under the device key bound in the `cnf` claim

## Demo-11 - SICPA Backend SD-JWT

The `d11_sicpa_backend` circuit targets the SD-JWT format produced by
the SICPA backend. It is structurally similar to `Demo-10`, but the
credential layout differs: the SICPA backend embeds the issuer's
public key directly in the JWT header, whereas the Swiyu SD-JWT uses
a generic header and binds the issuer via a Web3-DID in the payload.
Because the header is no longer constant across credentials, it is
exposed as a public input rather than reconstructed in the circuit.
See [`d11_sicpa_backend/README.md`](./d11_sicpa_backend/README.md) for
how to generate a fresh `Prover.toml` with `create-prover.py`.

The `main` function of our ZKP has the following inputs:

- Secret (only known to the holder):
  - `payload` — the raw JWT payload (JSON) as a bounded byte vector
  - `jwt_signature` — issuer ES256 signature over `header.payload`
  - `dob_salt`, `dob_value` — salt and value of the SD-JWT `birth_date`
    disclosure
  - `dob_sd_offset` — offset of the DOB digest in the `_sd` array of
    the payload
  - `x_offset`, `y_offset` — offsets of the device public-key X/Y
    coordinates in the `cnf` claim of the payload
  - `device_signature` — ES256 signature over the verifier challenge
- Public (known to the holder and the verifier):
  - `encoded_header` — base64url-encoded JWT header (carries the
    issuer's public key in the SICPA format)
  - `issuer_pub_x`, `issuer_pub_y` — issuer's P-256 public key
  - `now_date` — current date in `YYYYMMDD` form
  - `challenge_nonce` — 32-byte challenge from the verifier
- Calculated in the circuit
  - the base64url-encoded `header.payload` signing input, formed by
    joining `encoded_header` and the encoded `payload` with a `.`
  - the base64url-encoded SD-JWT disclosure for `birth_date` and its
    sha256 digest
  - the device public key, base64url-decoded from the `cnf` claim
- Proof
  - the `jwt_signature` is a valid ES256 signature by the issuer over
    `encoded_header.encoded_payload`
  - the salted disclosure for `birth_date` hashes to the digest stored
    at `dob_sd_offset` in the payload's `_sd` array
  - the `dob_value` corresponds to an age of at least 25 years at
    `now_date`
  - the `device_signature` is a valid ES256 signature over the
    `challenge_nonce` under the device key bound in the `cnf` claim
