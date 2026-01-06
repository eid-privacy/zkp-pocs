use std::error::Error;

use docknetwork::*;

// G3.2 - A complete test of the ECDSA signature verification.
#[test]
fn c03_proof_holder() -> Result<(), Box<dyn Error>> {
    let mut stats = Stats::start("c03_proof_holder");

    let mut common = Common::new();
    stats.mark_setup();

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
    stats.mark_proof_create();

    // Holder sends the proof to the verifier, which checks it.
    common.verifier_check_proofs(&message, &presentation_closed, &proof);
    stats.mark_verify();

    // Calculate proof size (BBS + ECDSA proofs)
    let bbs_sizes = presentation_closed.get_sizes();
    let ecdsa_sizes = proof.get_sizes();
    let total_size: usize = bbs_sizes.values().sum::<usize>() + ecdsa_sizes.values().sum::<usize>();
    stats.set_proof_size(total_size);

    stats.print();

    Ok(())
}
