#!/usr/bin/env python3

import glob
import hashlib
import json
import os

import common
import toml


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
    message_hash = hashlib.sha256(cred_bytes).digest()
    signature_bytes = bytes.fromhex(cred["signature_issuer"])
    print(f"Credential: {cred['credential_string'][0:5]}...")
    print(f"  Hash: {message_hash.hex()}")

    # Verify signature cryptographically
    r = int.from_bytes(signature_bytes[:32], "big")
    s = int.from_bytes(signature_bytes[32:], "big")

    # Convert compact signature (r||s) to DER format for verification
    def encode_der_integer(value):
        """Encode an integer as DER format"""
        value_bytes = value.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
        if value_bytes[0] & 0x80:  # High bit set, need padding
            value_bytes = b"\x00" + value_bytes
        return bytes([0x02, len(value_bytes)]) + value_bytes

    r_der = encode_der_integer(r)
    s_der = encode_der_integer(s)
    der_sig = bytes([0x30, len(r_der) + len(s_der)]) + r_der + s_der

    try:
        pubkey.verify(der_sig, message_hash, hasher=None)
        print("  Signature verification: PASSED")
    except Exception as e:
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
        with open(os.path.join(circuit, "src", "constants.nr"), "w") as f:
            constants = [
                "REVOCATION_LIST_IDS",
                "CREDENTIAL_LEN_FIRST",
                "CREDENTIAL_POS_FIRST",
                "CREDENTIAL_LEN_LAST",
                "CREDENTIAL_POS_LAST",
                "CREDENTIAL_LEN_DOB",
                "CREDENTIAL_POS_DOB",
                "CREDENTIAL_LEN_DEVICE_PUB_X",
                "CREDENTIAL_POS_DEVICE_PUB_X",
                "CREDENTIAL_LEN_DEVICE_PUB_Y",
                "CREDENTIAL_POS_DEVICE_PUB_Y",
                "CREDENTIAL_LEN_CRED_ID",
                "CREDENTIAL_POS_CRED_ID",
                "CREDENTIAL_LEN",
            ]
            for name in constants:
                f.write(f"pub global {name}: u32 = {getattr(common, name)};\n")
