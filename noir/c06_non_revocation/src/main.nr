use sha256::sha256_var;
mod constants;

global CREDENTIAL_LENGTH: u32 = 218;
global REVOCATION_LIST_LENGTH_WO_SIG: u32 = 8 + 8 + constants::REVOCATION_LIST_IDS / 8;
global REVOCATION_LIST_LENGTH: u32 = REVOCATION_LIST_LENGTH_WO_SIG + 64;
global REVOCATION_LIST_VALIDITY: u64 = 86400 * 7;

fn main(
    // Private inputs
    credential_string: str<CREDENTIAL_LENGTH>,
    revocation_list: [u8; REVOCATION_LIST_LENGTH],
    // Public inputs
    current_date: pub u64,
    pubkey_issuer_x: pub [u8; 32],
    pubkey_issuer_y: pub [u8; 32],
) {
    // Step 1: Read the ID of the credential and the start of the list
    let cred_id = hex_to_u64(credential_string.as_bytes(), 202);
    let list_start = Field::from_be_bytes::<8>(slice(revocation_list, 0)) as u64;

    // Step 2: Assert that the list contains the ID of the credential
    assert(list_start <= cred_id);
    // Relative index to the start of the list.
    let revocation_index_u64 = cred_id - list_start;
    assert(revocation_index_u64 < constants::REVOCATION_LIST_IDS as u64);
    let revocation_index = revocation_index_u64 as u32;

    // Step 3: Check the credential ID bit
    let revocation_byte = revocation_list[16 + revocation_index / 8];
    let revocation_bit = 1 << (revocation_index % 8);
    assert(revocation_byte & revocation_bit as u8 == 0);

    // Step 4: Verify the freshness of the list
    let list_date = Field::from_be_bytes::<8>(slice(revocation_list, 8)) as u64;
    assert(current_date < list_date + REVOCATION_LIST_VALIDITY);

    // Step 5: Calculate the hash of the revocation list
    let revocation_hash: [u8; 32] =
        sha256_var(revocation_list, REVOCATION_LIST_LENGTH_WO_SIG).into();

    // Step 6: Verify ECDSA signature on the revocation list
    let signature_valid = std::ecdsa_secp256k1::verify_signature(
        pubkey_issuer_x,
        pubkey_issuer_y,
        slice(revocation_list, REVOCATION_LIST_LENGTH_WO_SIG),
        revocation_hash,
    );
    assert(signature_valid);
}

fn slice<let IN: u32, let OUT: u32>(input: [u8; IN], start: u32) -> [u8; OUT] {
    let mut out = [0u8; OUT];
    for i in 0..OUT {
        out[i] = input[start + i];
    }
    out
}

fn hex_to_u64(hex_str: [u8; CREDENTIAL_LENGTH], start: u32) -> u64 {
    let mut result = 0u64;
    for i in 0..8 {
        let high_nibble = decode_nibble(hex_str[start + 2 * i]);
        let low_nibble = decode_nibble(hex_str[start + 2 * i + 1]);
        result = (result << 8) + ((high_nibble << 4) + low_nibble) as u64;
    }
    result
}

fn decode_nibble(hex_char: u8) -> u8 {
    (hex_char & 0x0F) + (hex_char >> 6) * 9
}
