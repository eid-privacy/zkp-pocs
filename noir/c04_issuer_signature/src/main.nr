use sha256::sha256_var;

global CREDENTIAL_LENGTH: u32 = 218;

fn main(
    // Private inputs
    credential_string: str<CREDENTIAL_LENGTH>,
    signature_issuer: [u8; 64],
    // Public inputs
    pubkey_issuer_x: pub [u8; 32],
    pubkey_issuer_y: pub [u8; 32],
) {
    // Step 1: Calculate the credential hash
    let credential_hash: [u8; 32] =
        sha256_var(credential_string.as_bytes(), CREDENTIAL_LENGTH).into();

    // Step 2: Verify ECDSA signature on the credential hash
    let signature_valid = std::ecdsa_secp256k1::verify_signature(
        pubkey_issuer_x,
        pubkey_issuer_y,
        signature_issuer,
        credential_hash,
    );
    assert(signature_valid);
}
