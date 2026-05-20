import argparse
import json
import os
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

REVOCATION_LIST_IDS = 1024
CREDENTIAL_LEN_FIRST = 32
CREDENTIAL_POS_FIRST = 0
CREDENTIAL_LEN_LAST = 32
CREDENTIAL_POS_LAST = CREDENTIAL_POS_FIRST + CREDENTIAL_LEN_FIRST
CREDENTIAL_LEN_DOB = 10
CREDENTIAL_POS_DOB = CREDENTIAL_POS_LAST + CREDENTIAL_LEN_LAST
CREDENTIAL_LEN_DEVICE_PUB_X = 64
CREDENTIAL_POS_DEVICE_PUB_X = CREDENTIAL_POS_DOB + CREDENTIAL_LEN_DOB
CREDENTIAL_LEN_DEVICE_PUB_Y = 64
CREDENTIAL_POS_DEVICE_PUB_Y = CREDENTIAL_POS_DEVICE_PUB_X + CREDENTIAL_LEN_DEVICE_PUB_X
CREDENTIAL_LEN_CRED_ID = 16
CREDENTIAL_POS_CRED_ID = CREDENTIAL_POS_DEVICE_PUB_Y + CREDENTIAL_LEN_DEVICE_PUB_Y
CREDENTIAL_LEN = CREDENTIAL_POS_CRED_ID + CREDENTIAL_LEN_CRED_ID

TIME_NOW = int(datetime(2025, 11, 6, 18, 20).timestamp())

# secp256r1 (P-256) curve order
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def sign_p256(private_key, message: bytes) -> bytes:
    """Sign message with secp256r1, returning low-S normalized 64-byte r||s."""
    der_sig = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    if s > _P256_ORDER // 2:
        s = _P256_ORDER - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def parse_args(description, circuit=False):
    parser = argparse.ArgumentParser(description)
    parser.add_argument(
        "key_dir",
        nargs="?",
        help="Destination directory to save issuer keys",
        default="credentials",
    )
    if circuit:
        parser.add_argument(
            "circuit_dir", nargs="?", help="Circuit directory", default="."
        )

    args = parser.parse_args()
    if args.key_dir is None:
        print("Need to give a valid directory to save issuer keys")
        exit(1)

    if circuit:
        return [os.path.abspath(args.key_dir), os.path.abspath(args.circuit_dir)]
    else:
        return os.path.abspath(args.key_dir)


def load_keys(dirname, filename):
    """Load keys from JSON file."""
    try:
        with open(os.path.join(dirname, filename), "r") as f:
            keys = json.load(f)

        private_key_bytes = bytes.fromhex(keys["private_key"])
        private_value = int.from_bytes(private_key_bytes, "big")
        private_key_obj = ec.derive_private_key(private_value, ec.SECP256R1())
        keys["private_key_obj"] = private_key_obj
        keys["public_key_obj"] = private_key_obj.public_key()

        return keys

    except FileNotFoundError:
        print(f"❌ Error: {filename} not found. Run 1-create-keys.py first.")
        exit(1)


def load_issuer_keys(dirname):
    """Load issuer keys from JSON file."""
    return load_keys(dirname, "keys_issuer.json")


def load_device_keys(dirname, label):
    """Load device keys from JSON file."""
    return load_keys(dirname, f"keys_device_{label}.json")
