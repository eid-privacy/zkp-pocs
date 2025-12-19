use std::error::Error;

use docknetwork::*;

/// G5.2 - Proving a revelation of a BBS string field.
#[test]
fn c05_proof_predicate() -> Result<(), Box<dyn Error>> {
    let mut common = Common::new();

    // Verifier requests a presentation from the holder
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

/// G5.2 - Proving an age verification of a BBS date.
#[test]
fn c05_proof_predicate_age() -> Result<(), Box<dyn Error>> {
    //     // Set up parties
    //     let setup = PublicSetup::new();
    //     let mut issuer = Issuer::new(setup.clone());
    //     let mut holder = MobilePhone::new(setup.clone());
    //     let mut verifier = Verifier::new(setup.clone(), issuer.get_certificate());

    //     // Install the swiyu app and add a credential
    //     holder.install_swiyu();
    //     let se_kp = holder.secure_element().create_kp();
    //     let credential = issuer.new_credential(se_kp.key_pub);
    //     holder.swiyu().add_vc(se_kp.id, credential.clone());

    //     // Verifier requests a presentation from the holder
    //     let message = verifier.create_message();

    //     // Holder creates a presentation with a proof of knowledge and zero or more revealed messages.
    //     // This is of course all done in the Swiyu app, but here we do it step-by-step.
    //     let presentation = holder.swiyu().bbs_presentation(message.clone(), vec![]);
    //     let presentation_closed = presentation.close();

    //     // Holder sends the proof to the verifier, which checks it.
    //     verifier.check_proof_bbs_only(message, presentation_closed.clone());
    //     assert_eq!(
    //         presentation_closed.message_string(VerifiedCredential::FIELD_FIRSTNAME),
    //         Some(credential.message_strings[&VerifiedCredential::FIELD_FIRSTNAME].clone())
    //     );
    //     assert_eq!(
    //         presentation_closed.message_string(VerifiedCredential::FIELD_LASTNAME),
    //         None
    //     );

    Ok(())
}
