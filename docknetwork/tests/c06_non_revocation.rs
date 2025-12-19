use std::error::Error;

use docknetwork::*;

/// G6 - Proving non-revocation using KB Universal Accumulator.
/// The credential ID is not in the revocation accumulator, so we can prove
/// non-membership (not revoked).
#[test]
fn c06_proof_non_revocation() -> Result<(), Box<dyn Error>> {
    let mut stats = Stats::start("c06_proof_non_revocation");

    let mut common = Common::new();
    stats.mark_setup();

    // Create non-revocation proof (prover/holder side)
    // This proves the credential ID is NOT in the revocation accumulator
    let proof = common.create_non_revocation_proof();
    stats.mark_proof_create();

    // Verify non-revocation proof (verifier side)
    common.verify_non_revocation_proof(&proof);
    stats.mark_verify();

    // Calculate proof size
    let total_size = proof.get_size();
    stats.set_proof_size(total_size);

    stats.print();

    Ok(())
}
