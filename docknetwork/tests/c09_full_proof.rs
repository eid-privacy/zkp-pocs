use std::error::Error;

use docknetwork::*;

#[test]
fn c09_proof_full() -> Result<(), Box<dyn Error>> {
    let mut stats = Stats::start("c09_proof_full");

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
