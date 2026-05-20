#!/usr/bin/env python3

import glob
import json
import os

import common
import toml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def prover_fixed(time_now, pubkey_issuer, credentials, dirname):
    for i, cred in enumerate(credentials):
        print(
            f"Storing fixed to {dirname}/Prover_{i}: {cred['credential_string'][0:5]}"
        )
        with open(os.path.join(dirname, f"Prover_{i}.toml"), "w") as f:
            toml.dump(
                {
                    "current_date": time_now,
                    "pubkey_issuer_x": pubkey_issuer[0],
                    "pubkey_issuer_y": pubkey_issuer[1],
                    **cred,
                },
                f,
            )


def verify_credential(cred):
    cred_bytes = cred["credential_string"].encode("utf-8")
    signature_bytes = bytes.fromhex(cred["signature_issuer"])
    print(f"Credential: {cred['credential_string'][0:5]}...")

    r = int.from_bytes(signature_bytes[:32], "big")
    s = int.from_bytes(signature_bytes[32:], "big")
    der_sig = encode_dss_signature(r, s)

    try:
        pubkey.verify(der_sig, cred_bytes, ec.ECDSA(hashes.SHA256()))
        print("  Signature verification: PASSED")
    except InvalidSignature as e:
        print(f"  Signature verification: FAILED ({e})")


def get_credentials(dirname, pattern):
    pattern = os.path.join(dirname, pattern)
    credentials = []
    for cred_path in sorted(glob.glob(pattern)):
        with open(cred_path, "r", encoding="utf-8") as f:
            cred = json.loads(f.read())
            # Convert all fields starting with "0x" to binary
            for key, value in cred.items():
                if isinstance(value, str) and value.startswith("0x"):
                    cred[key] = bytes.fromhex(value[2:])

            credentials.append(cred)
            # verify_credential(cred)
    return credentials


if __name__ == "__main__":
    print("Creating various credentials and sign them...")
    [KEY_DIR, CIRCUIT_DIR] = common.parse_args("Create credentials.", True)
    keys = common.load_issuer_keys(KEY_DIR)
    pubkey_issuer_xy = [
        bytes.fromhex(keys["public_key_x"]),
        bytes.fromhex(keys["public_key_y"]),
    ]
    pubkey = keys["public_key_obj"]
    print(keys["public_key_x"])
    print(keys["public_key_y"])

    credentials_device_fixed = get_credentials(KEY_DIR, "credential_device_fixed*.json")

    circuits = [
        d for d in glob.glob(os.path.join(CIRCUIT_DIR, "c*_*")) if os.path.isdir(d)
    ]
    for circuit in circuits:
        base = os.path.basename(circuit)
        prover_fixed(
            common.TIME_NOW, pubkey_issuer_xy, credentials_device_fixed, circuit
        )
