#!/usr/bin/env python3
"""
Generate secp256r1 ECDSA key pair for credential issuer.
Outputs the keys in formats suitable for Noir circuit inputs.
"""

import os

from cryptography.hazmat.primitives.asymmetric import ec
from common import parse_args


def generate_keys():
    """Generate a new secp256r1 key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_numbers = private_key.private_numbers()

    private_key_bytes = private_numbers.private_value.to_bytes(32, byteorder="big")
    pub = private_numbers.public_numbers
    x_coord = pub.x.to_bytes(32, byteorder="big")
    y_coord = pub.y.to_bytes(32, byteorder="big")

    return {
        "private_key": private_key_bytes.hex(),
        "public_key_x": x_coord.hex(),
        "public_key_y": y_coord.hex(),
        "private_key_obj": private_key,
        "public_key_obj": private_key.public_key(),
    }


def save_keys_to_file(keys, filename="issuer_keys.json"):
    """Save keys to JSON file (excluding the key objects)."""
    import json

    key_data = {
        "private_key": keys["private_key"],
        "public_key_x": keys["public_key_x"],
        "public_key_y": keys["public_key_y"],
    }

    with open(filename, "w") as f:
        json.dump(key_data, f, indent=2)

    print(f"Keys saved to {filename}")


if __name__ == "__main__":
    KEY_DIR = str(parse_args("Generate secp256r1 issuer key pair."))
    os.makedirs(KEY_DIR, exist_ok=True)

    print("Generating secp256r1 issuer key pair...")

    keys = generate_keys()
    save_keys_to_file(keys, os.path.join(KEY_DIR, "keys_issuer.json"))

    keys = generate_keys()
    save_keys_to_file(keys, os.path.join(KEY_DIR, "keys_device_alice.json"))

    keys = generate_keys()
    save_keys_to_file(keys, os.path.join(KEY_DIR, "keys_device_bob.json"))
