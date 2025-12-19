use std::error::Error;

use docknetwork::*;

#[test]
fn c06_proof_non_revocation() -> Result<(), Box<dyn Error>> {
    let mut common = Common::new();
    let message = VerifierMessage::new("Verifier");

    // Holder creates a presentation with a proof of knowledge and no revealed messages.
    let presentation = common
        .holder_bbs_presentation(message.clone(), vec![VerifiedCredential::FIELD_FIRSTNAME])
        .close();

    // Holder sends the proof to the verifier, which checks it.
    common.verifier_check_proof_bbs(&message, &presentation);
    assert_eq!(
        presentation.message_string(VerifiedCredential::FIELD_FIRSTNAME),
        Some(common.credential.message_strings[&VerifiedCredential::FIELD_FIRSTNAME].clone())
    );
    assert_eq!(
        presentation.message_string(VerifiedCredential::FIELD_LASTNAME),
        None
    );

    Ok(())
}
