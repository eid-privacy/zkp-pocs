use std::error::Error;

use docknetwork::*;

// G4.2 - A BBS signature verification.
#[test]
fn c04_proof_credential() -> Result<(), Box<dyn Error>> {
    let mut common = Common::new();

    // Verifier requests a presentation from the holder
    let message = VerifierMessage::new("Verifier");

    // Holder creates a presentation with a proof of knowledge and no revealed messages.
    let presentation = common
        .holder_bbs_presentation(message.clone(), vec![])
        .close();

    // Holder sends the proof to the verifier, which checks it.
    common.verifier_check_proof_bbs(&message, &presentation);

    Ok(())
}
