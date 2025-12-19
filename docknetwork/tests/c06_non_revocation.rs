use std::error::Error;

use docknetwork::*;

/// G6 - Proving non-revocation using KB Universal Accumulator.
/// The credential ID is not in the revocation accumulator, so we can prove
/// non-membership (not revoked).
#[test]
fn c06_proof_non_revocation() -> Result<(), Box<dyn Error>> {
    let mut common = Common::new();

    // Print the credential ID for debugging
    println!(
        "Credential ID: {}",
        common.credential.message_u64[&VerifiedCredential::FIELD_CREDENTIAL_ID]
    );

    // Create non-revocation proof (prover/holder side)
    // This proves the credential ID is NOT in the revocation accumulator
    let proof = common.create_non_revocation_proof();

    // Verify non-revocation proof (verifier side)
    common.verify_non_revocation_proof(&proof);

    println!("Non-revocation proof verified: credential is not revoked");

    Ok(())
}
