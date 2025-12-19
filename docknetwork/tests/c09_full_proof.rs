use std::error::Error;

use chrono::TimeZone;
use docknetwork::*;

/// G9 - Complete proof combining all verification mechanisms:
/// - ECDSA signature (holder binding)
/// - Age verification (predicate proof)
/// - Non-revocation (exclusion proof)
/// - BBS signature (credential proof)
#[test]
fn c09_proof_full() -> Result<(), Box<dyn Error>> {
    let mut stats = Stats::start("c09_proof_full");

    let mut common = Common::new();
    stats.mark_setup();

    // Verifier requests a presentation from the holder
    let message = VerifierMessage::new("Verifier");

    // ===== PROOF CREATION (Holder/Prover Side) =====

    // 1. Create BBS presentation with no revealed messages
    let presentation = common.holder_bbs_presentation(message.clone(), vec![]);

    // 2. Create ECDSA signature and proof (holder binding)
    let signature = common.holder_sign(message.clone());
    let ecdsa_proof = ECDSAProof::new(
        &mut common.setup,
        &common.kp_holder.public_key,
        &common.credential,
        &presentation,
        &signature,
        &message,
    );

    // 3. Create age verification proof (18+ check)
    // Fixed threshold: January 1, 2025 minus 18 years = January 1, 2007
    let eighteen_years_ago = chrono::Utc
        .with_ymd_and_hms(2007, 1, 1, 0, 0, 0)
        .single()
        .unwrap()
        .timestamp() as u64;

    let age_proof = common.create_age_proof(eighteen_years_ago);

    // 4. Create non-revocation proof (exclusion proof)
    let non_revocation_proof = common.create_non_revocation_proof();

    // Close the BBS presentation
    let presentation_closed = presentation.close();

    stats.mark_proof_create();

    // ===== VERIFICATION (Verifier Side) =====

    // 1. Verify ECDSA proof and BBS presentation together
    common.verifier_check_proofs(&message, &presentation_closed, &ecdsa_proof);

    // 2. Verify BBS proof (credential validity)
    common.verifier_check_proof_bbs(&message, &presentation_closed);

    // 3. Verify age proof
    common.verify_age_proof(&age_proof, eighteen_years_ago);

    // 4. Verify non-revocation proof
    common.verify_non_revocation_proof(&non_revocation_proof);

    stats.mark_verify();

    // ===== CALCULATE TOTAL PROOF SIZE =====
    let bbs_sizes = presentation_closed.get_sizes();
    let ecdsa_sizes = ecdsa_proof.get_sizes();
    let age_size = age_proof.get_size();
    let non_revocation_size = non_revocation_proof.get_size();

    let total_size: usize = bbs_sizes.values().sum::<usize>()
        + ecdsa_sizes.values().sum::<usize>()
        + age_size
        + non_revocation_size;

    stats.set_proof_size(total_size);

    stats.print();

    Ok(())
}
