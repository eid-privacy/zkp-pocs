use std::error::Error;

use chrono::TimeZone;
use docknetwork::*;

/// G5.2 - Proving a revelation of a BBS string field.
#[test]
fn c05_proof_predicate() -> Result<(), Box<dyn Error>> {
    let mut stats = Stats::start("c05_proof_predicate");

    let mut common = Common::new();
    stats.mark_setup();

    let message = VerifierMessage::new("Verifier");

    // Holder creates a presentation with a proof of knowledge and no revealed messages.
    let presentation = common
        .holder_bbs_presentation(message.clone(), vec![VerifiedCredential::FIELD_FIRSTNAME])
        .close();
    stats.mark_proof_create();

    // Holder sends the proof to the verifier, which checks it.
    common.verifier_check_proof_bbs(&message, &presentation);
    stats.mark_verify();

    assert_eq!(
        presentation.message_string(VerifiedCredential::FIELD_FIRSTNAME),
        Some(common.credential.message_strings[&VerifiedCredential::FIELD_FIRSTNAME].clone())
    );
    assert_eq!(
        presentation.message_string(VerifiedCredential::FIELD_LASTNAME),
        None
    );

    // Calculate proof size
    let sizes = presentation.get_sizes();
    let total_size: usize = sizes.values().sum();
    stats.set_proof_size(total_size);

    stats.print();

    Ok(())
}

/// G5.2 - Proving an age verification using a BBS date field with bound checks.
/// This test proves that the holder is at least 18 years old without revealing
/// the exact date of birth.
#[test]
fn c05_proof_predicate_age() -> Result<(), Box<dyn Error>> {
    let mut stats = Stats::start("c05_proof_predicate_age");

    let mut common = Common::new();
    stats.mark_setup();

    // Fixed threshold: January 1, 2025 minus 18 years = January 1, 2007
    // To be at least 18 on Jan 1, 2025, holder must have been born before Jan 1, 2007.
    let eighteen_years_ago = chrono::Utc
        .with_ymd_and_hms(2007, 1, 1, 0, 0, 0)
        .single()
        .unwrap()
        .timestamp() as u64;

    // The test credential has DOB = Dec 1, 2001, so the holder is 23 years old
    // (as of Jan 1, 2025) and should pass the 18+ check.

    // Create age proof (prover/holder side)
    let age_proof = common.create_age_proof(eighteen_years_ago);
    stats.mark_proof_create();

    // Verify age proof (verifier side)
    common.verify_age_proof(&age_proof, eighteen_years_ago);
    stats.mark_verify();

    // Calculate proof size
    let total_size = age_proof.get_size();
    stats.set_proof_size(total_size);

    stats.print();

    Ok(())
}
