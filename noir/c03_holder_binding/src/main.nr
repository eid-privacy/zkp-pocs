global CREDENTIAL_LENGTH: u32 = 202;

fn main(
    // Private inputs
    credential_string: str<CREDENTIAL_LENGTH>,
    signature_device: [u8; 64],
    // Public input
    challenge_hash: pub [u8; 32],
) {
    // Step 1: Verify device signature on the challenge hash
    // Extract public key from credential_raw from hex encoded values in position
    // 74 to 138 (32 bytes X, 32 bytes Y).
    let pubkey_device_x = decode_hex_32(credential_string.as_bytes(), 74);
    let pubkey_device_y = decode_hex_32(credential_string.as_bytes(), 138);

    let signature_device_valid = std::ecdsa_secp256k1::verify_signature(
        pubkey_device_x,
        pubkey_device_y,
        signature_device,
        challenge_hash,
    );
    assert(signature_device_valid);
}

fn decode_hex_32(hex_str: [u8; CREDENTIAL_LENGTH], start: u32) -> [u8; 32] {
    let mut result: [u8; 32] = [0u8; 32];
    for i in 0..32 {
        let high_nibble = decode_nibble(hex_str[start + 2 * i]);
        let low_nibble = decode_nibble(hex_str[start + 2 * i + 1]);
        result[i] = high_nibble * 16 + low_nibble;
    }
    result
}

fn decode_nibble(hex_char: u8) -> u8 {
    (hex_char & 0x0F) + (hex_char >> 6) * 9
}
