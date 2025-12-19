use std::error::Error;

use docknetwork::*;

// G3.2 - A complete test of the ECDSA signature verification.
#[test]
fn c03_proof_holder() -> Result<(), Box<dyn Error>> {
    let mut common = Common::new();

    // Verifier requests a presentation from the holder
    let message = VerifierMessage::new("Verifier");

    // Holder creates a presentation with a proof of knowledge and no revealed messages.
    let presentation = common.holder_bbs_presentation(message.clone(), vec![]);
    let signature = common.holder_sign(message.clone());
    let proof = ECDSAProof::new(
        &mut common.setup,
        &common.kp_holder.public_key,
        &common.credential,
        &presentation,
        &signature,
        &message,
    );
    let presentation_closed = presentation.close();

    // Holder sends the proof to the verifier, which checks it.
    // TODO: Not sure if we can only do the ECDSA proof - probably this doesn't make sense.
    common.verifier_check_proofs(&message, &presentation_closed, &proof);

    Ok(())
}
