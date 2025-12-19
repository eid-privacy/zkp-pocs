use eid::{constants, decode_hex_32, hex_to_u64, slice};
use sha256::sha256_var;

fn main(
    // Private inputs
    credential_string: str<constants::CREDENTIAL_LEN>,
    revocation_list: [u8; eid::REVOCATION_LIST_LENGTH],
    signature_device: [u8; 64],
    signature_issuer: [u8; 64],
    // Public inputs
    challenge_hash: pub [u8; 32],
    current_date: pub u64,
    pubkey_issuer_x: pub [u8; 32],
    pubkey_issuer_y: pub [u8; 32],
) {
    // Device Signature
    // Step 1: Verify device signature on the challenge hash
    // Extract public key from credential_raw from hex encoded values in position
    // 74 to 138 (32 bytes X, 32 bytes Y).
    let pubkey_device_x = decode_hex_32(
        credential_string.as_bytes(),
        constants::CREDENTIAL_POS_DEVICE_PUB_X,
    );
    let pubkey_device_y = decode_hex_32(
        credential_string.as_bytes(),
        constants::CREDENTIAL_POS_DEVICE_PUB_Y,
    );

    let signature_device_valid = std::ecdsa_secp256k1::verify_signature(
        pubkey_device_x,
        pubkey_device_y,
        signature_device,
        challenge_hash,
    );
    assert(signature_device_valid);

    // Issuer Signature
    // Step 1: Calculate the credential hash
    let credential_hash: [u8; 32] =
        sha256_var(credential_string.as_bytes(), constants::CREDENTIAL_LEN).into();

    // Step 2: Verify ECDSA signature on the credential hash
    let signature_valid = std::ecdsa_secp256k1::verify_signature(
        pubkey_issuer_x,
        pubkey_issuer_y,
        signature_issuer,
        credential_hash,
    );
    assert(signature_valid);

    // Age verification
    // Calculate the age in seconds
    let mut birth_timestamp: u64 = 0;
    for i in 0..constants::CREDENTIAL_LEN_DOB {
        birth_timestamp = birth_timestamp * 10
            + credential_string.as_bytes()[i + constants::CREDENTIAL_POS_DOB] as u64
            - 48;
    }
    assert(birth_timestamp <= current_date);
    let age_seconds = current_date - birth_timestamp;

    // Ignoring leap years and check against 18 years of duration: 365.25 * 24 * 3600 = 31,557,600
    let seconds_per_year = 31557600;
    let min_age_seconds = 18 * seconds_per_year;
    assert(age_seconds >= min_age_seconds);

    // Non-revocation test
    // Step 1: Read the ID of the credential and the start of the list
    let cred_id = hex_to_u64(
        credential_string.as_bytes(),
        constants::CREDENTIAL_POS_CRED_ID,
    );
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
    assert(current_date < list_date + eid::REVOCATION_LIST_VALIDITY);

    // Step 5: Calculate the hash of the revocation list
    let revocation_hash: [u8; 32] =
        sha256_var(revocation_list, eid::REVOCATION_LIST_LENGTH_WO_SIG).into();

    // Step 6: Verify ECDSA signature on the revocation list
    let signature_valid = std::ecdsa_secp256k1::verify_signature(
        pubkey_issuer_x,
        pubkey_issuer_y,
        slice(revocation_list, eid::REVOCATION_LIST_LENGTH_WO_SIG),
        revocation_hash,
    );
    assert(signature_valid);
}
