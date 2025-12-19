use ark_bls12_381::{Bls12_381, Fr as BlsFr, G1Affine as BlsG1Affine};
use ark_ec::{AffineRepr, CurveGroup, short_weierstrass::Affine};
use ark_ff::PrimeField;
use ark_secp256r1::{Affine as SecP256Affine, Fq, Fr as SecP256Fr};
use ark_serialize::{CanonicalSerialize, Compress, SerializationError};
use ark_std::{
    UniformRand,
    io::Write,
    rand::{SeedableRng, rngs::StdRng},
    vec::Vec,
};
use base64::prelude::*;
use bbs_plus::{
    error::BBSPlusError,
    prelude::SignatureG1,
    proof::{PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol},
    setup::{KeypairG2, PublicKeyG2, SecretKey, SignatureParamsG1},
};
use blake2::Blake2b512;
use bulletproofs_plus_plus::prelude::SetupParams as BppSetupParams;
use chrono::TimeZone;
use dock_crypto_utils::{
    commitment::PedersenCommitmentKey,
    signature::MessageOrBlinding,
    transcript::{Transcript, new_merlin_transcript},
};
use equality_across_groups::{
    ec::commitments::{
        PointCommitment, PointCommitmentWithOpening, from_base_field_to_scalar_field,
    },
    eq_across_groups::ProofLargeWitness,
    pok_ecdsa_pubkey::{
        PoKEcdsaSigCommittedPublicKey, PoKEcdsaSigCommittedPublicKeyProtocol, TransformedEcdsaSig,
    },
    tom256::{Affine as Tom256Affine, Config as Tom256Config},
};
pub use kvac::bbs_sharp::ecdsa;
use proof_system::{
    prelude::{
        EqualWitnesses, MetaStatement, MetaStatements, Witness, WitnessRef, Witnesses,
        bbs_plus::{PoKBBSSignatureG1Prover, PoKBBSSignatureG1Verifier},
    },
    proof::Proof,
    proof_spec::ProofSpec,
    statement::{
        Statements, bound_check_bpp::BoundCheckBpp,
        ped_comm::PedersenCommitment as PedersenCommitmentStmt,
    },
    witness::PoKBBSSignatureG1,
};

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug)]
pub struct Common {
    pub setup: PublicSetup,
    pub kp_issuer: KeypairG2<Bls12_381>,
    pub kp_holder: P256Keypair,
    pub credential: VerifiedCredential,
}

impl Common {
    pub fn new() -> Self {
        let mut setup = PublicSetup::new();
        let kp_issuer =
            KeypairG2::<Bls12_381>::generate_using_rng(&mut setup.rng, &setup.sig_params_g1);
        let kp_holder = P256Keypair::new(&mut setup);
        let credential =
            VerifiedCredential::new(&mut setup, kp_holder.public_key, &kp_issuer.secret_key);
        Self {
            setup,
            kp_issuer,
            kp_holder,
            credential,
        }
    }

    pub fn holder_bbs_presentation(
        &mut self,
        message: VerifierMessage,
        reveal: Vec<usize>,
    ) -> BBSPresentation {
        BBSPresentation::new(&mut self.setup, &self.credential, message, reveal)
    }

    pub fn holder_sign(&mut self, msg: VerifierMessage) -> ecdsa::Signature {
        ecdsa::Signature::new_prehashed(
            &mut self.setup.rng,
            (&msg).into(),
            self.kp_holder.secret_key,
        )
    }

    pub fn verifier_check_proofs(
        &self,
        verifier_message: &VerifierMessage,
        bbs_presentation: &BBSPresentation,
        ecdsa_proof: &ECDSAProof,
    ) {
        self.verifier_check_proof_bbs(verifier_message, bbs_presentation);
        self.verifier_check_proof_ecdsa(verifier_message, bbs_presentation, ecdsa_proof);
    }

    pub fn verifier_check_proof_bbs(
        &self,
        verifier_message: &VerifierMessage,
        bbs_presentation: &BBSPresentation,
    ) {
        bbs_presentation
            .verify(
                self.setup.clone(),
                self.kp_issuer.public_key.clone(),
                &verifier_message.into(),
            )
            .expect("Verification of BBS proof failed");
    }

    pub fn verifier_check_proof_ecdsa(
        &self,
        verifier_message: &VerifierMessage,
        bbs_presentation: &BBSPresentation,
        ecdsa_proof: &ECDSAProof,
    ) {
        ecdsa_proof.verify(
            self.setup.clone(),
            verifier_message.into(),
            bbs_presentation,
            &self.kp_issuer.public_key,
        );
    }

    /// Create an age proof proving the holder's date of birth is before `max_dob`.
    /// This proves the holder is at least `(now - max_dob)` years old.
    pub fn create_age_proof(&mut self, max_dob: u64) -> AgeProof {
        AgeProof::new(
            &mut self.setup,
            &self.credential,
            &self.kp_issuer.public_key,
            max_dob,
        )
    }

    /// Verify an age proof for the given `max_dob` bound.
    pub fn verify_age_proof(&self, proof: &AgeProof, max_dob: u64) {
        proof.verify(&self.setup, &self.kp_issuer.public_key, max_dob);
    }
}

#[derive(Debug)]
pub struct P256Keypair {
    pub secret_key: SecP256Fr,
    pub public_key: SecP256Affine,
}

impl P256Keypair {
    pub fn new(setup: &mut PublicSetup) -> Self {
        // let sk = SecP256Fr::rand(&mut StdRng::seed_from_u64(0u64));
        // let key_pub = (ecdsa::Signature::generator() * sk).into_affine();
        let secret = SecP256Fr::rand(&mut setup.rng);
        let public = (ecdsa::Signature::generator() * secret).into_affine();

        Self {
            secret_key: secret,
            public_key: public,
        }
    }
}

/// Globally known public values.
/// These values can be created by anyone and are needed by all actors.
#[derive(Clone, Debug)]
pub struct PublicSetup {
    /// Random Number Generator
    pub rng: StdRng,
    /// Parameters for the BBS signatures
    pub sig_params_g1: SignatureParamsG1<Bls12_381>,
    /// Bulletproof setup parameters - usually created by the verifier and then sent to the prover.
    pub bpp_setup_params: BppSetupParams<Affine<Tom256Config>>,
    /// Commitment generators for the Tom-256 keys
    pub comm_key_tom: PedersenCommitmentKey<Tom256Affine>,
    /// Commitment generators for the SecP256 keys
    pub comm_key_secp: PedersenCommitmentKey<SecP256Affine>,
    /// Commitment generators for the Bls12-381 keys
    pub comm_key_bls: PedersenCommitmentKey<BlsG1Affine>,
    /// Bulletproof setup parameters for BBS bound checks on Bls12-381 curve.
    pub bpp_setup_params_bls: BppSetupParams<BlsG1Affine>,
}

impl PublicSetup {
    // These constants define also the security level of the proofs created in [BBSPresentation].
    const WITNESS_BIT_SIZE: usize = 64;
    const CHALLENGE_BIT_SIZE: usize = 180;
    const ABORT_PARAM: usize = 8;
    const RESPONSE_BYTE_SIZE: usize = 32;
    const NUM_REPS: usize = 1;
    const NUM_CHUNKS: usize = 4;
    const BPP_BASE: u16 = 2;

    /// Create a new [PublicSetup]. It can also be [Clone]d, or created new.
    pub fn new() -> Self {
        let comm_key_tom = PedersenCommitmentKey::<Tom256Affine>::new::<Blake2b512>(b"test2");

        // Bulletproofs++ setup
        let base = PublicSetup::BPP_BASE;
        let mut bpp_setup_params =
            BppSetupParams::<Tom256Affine>::new_for_perfect_range_proof::<Blake2b512>(
                b"test",
                base,
                PublicSetup::WITNESS_BIT_SIZE as u16,
                PublicSetup::NUM_CHUNKS as u32,
            );
        bpp_setup_params.G = comm_key_tom.g;
        bpp_setup_params.H_vec[0] = comm_key_tom.h;

        // Bulletproofs++ setup for BBS bound checks on Bls12-381 curve
        let bpp_setup_params_bls =
            BppSetupParams::<BlsG1Affine>::new_for_perfect_range_proof::<Blake2b512>(
                b"bbs-bounds",
                base,
                PublicSetup::WITNESS_BIT_SIZE as u16,
                PublicSetup::NUM_CHUNKS as u32,
            );

        Self {
            sig_params_g1: SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(
                "eid-demo".as_bytes(),
                VerifiedCredential::FIELD_COUNT,
            ),
            rng: StdRng::seed_from_u64(0u64),
            bpp_setup_params,
            comm_key_tom,
            comm_key_secp: PedersenCommitmentKey::<SecP256Affine>::new::<Blake2b512>(b"test1"),
            comm_key_bls: PedersenCommitmentKey::<BlsG1Affine>::new::<Blake2b512>(b"test3"),
            bpp_setup_params_bls,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("JSON conversion error")
    }

    /// For the proofs it is important to enter all variables in the transcript, and then hash
    /// them to create a challenge.
    /// If the prover can modify values which are not part of the transcript, they might get
    /// an advantage and manage to create a wrong proof.
    fn append_transcript<T: Transcript + Clone + Write>(&self, pt: &mut T) {
        pt.append(b"comm_key_secp", &self.comm_key_secp);
        pt.append(b"comm_key_tom", &self.comm_key_tom);
        pt.append(b"comm_key_bls", &self.comm_key_bls);
        pt.append(b"bpp_setup_params", &self.bpp_setup_params);
    }
}

/// A [VerifiedCredential] is created by the [Issuer] and holds the public key of the
/// [MobilePhone] in a secure way.
/// We suppose that the first two positions are the x and y value of the holder's
/// public key.
#[derive(CanonicalSerialize, Debug, Clone)]
pub struct VerifiedCredential {
    /// The messages are the values hashed to a BlsFr scalar and are secret.
    /// Only the [Issuer] and the [MobilePhone] should know them.
    /// Except for the revealed messages, of course.
    pub messages: Vec<BlsFr>,
    /// Signature of the issuer on this credential.
    pub signature: SignatureG1<Bls12_381>,
    /// Contents of the messages which hold strings
    pub message_strings: BTreeMap<usize, String>,
    /// Contents of the messages which hold u64
    pub message_u64: BTreeMap<usize, u64>,
}

/// Numbering the fields in the VerifiedCredential.
impl VerifiedCredential {
    pub const FIELD_PUB_X: usize = 0;
    pub const FIELD_PUB_Y: usize = 1;
    pub const FIELD_FIRSTNAME: usize = 2;
    pub const FIELD_LASTNAME: usize = 3;
    pub const FIELD_DATEOFBIRTH: usize = 4;
    pub const FIELD_COUNT: u32 = 5;

    pub fn new(
        setup: &mut PublicSetup,
        key_pub: SecP256Affine,
        key_sec: &SecretKey<BlsFr>,
    ) -> Self {
        let pk_x = from_base_field_to_scalar_field::<Fq, BlsFr>(key_pub.x().unwrap());
        let pk_y = from_base_field_to_scalar_field::<Fq, BlsFr>(key_pub.y().unwrap());
        let mut generator = names::Generator::default();
        let (first, last) = (generator.next().unwrap(), generator.next().unwrap());
        let date_of_birth: u64 = chrono::Utc
            .with_ymd_and_hms(2001, 12, 1, 0, 0, 0)
            .single()
            .unwrap()
            .timestamp() as u64;
        let message_strings = BTreeMap::from([
            (VerifiedCredential::FIELD_FIRSTNAME, first.clone()),
            (VerifiedCredential::FIELD_LASTNAME, last.clone()),
        ]);
        let message_u64 = BTreeMap::from([(VerifiedCredential::FIELD_DATEOFBIRTH, date_of_birth)]);
        let messages = vec![
            pk_x,
            pk_y,
            (&VerifierMessage(first)).into(),
            (&VerifierMessage(last)).into(),
            date_of_birth.into(),
        ];
        VerifiedCredential {
            signature: SignatureG1::<Bls12_381>::new(
                &mut setup.rng,
                &messages,
                key_sec,
                &setup.sig_params_g1,
            )
            .unwrap(),
            messages,
            message_strings,
            message_u64,
        }
    }

    /// Returns the string of the given message. Only works for the first
    /// and last name. Returns `None` for the other fields.
    pub fn get_message_str(&self, field: usize) -> Option<String> {
        return self.message_strings.get(&field).cloned();
    }
}

/// The [VerifierMessage] is used both for the signature from the
/// [SecureElement] and in the [BBSPresentation].
/// This is a very simple implementation allowing to create scalars
/// for SecP256 and Bls12-381.
#[derive(Debug, Clone)]
pub struct VerifierMessage(String);

impl VerifierMessage {
    /// Create a new message with some kind of domain separation.
    pub fn new(domain: &str) -> Self {
        Self(format!(
            "{domain}: Proof request at {}",
            chrono::Utc::now().to_rfc3339()
        ))
    }
}

/// Allow to create a Bls12-381 scalar.
impl Into<BlsFr> for &VerifierMessage {
    fn into(self) -> BlsFr {
        let hash = Sha256::digest(self.0.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash[..32]);
        BlsFr::from_le_bytes_mod_order(&bytes)
    }
}

/// Allow to create a SecP256 scalar.
impl Into<SecP256Fr> for &VerifierMessage {
    fn into(self) -> SecP256Fr {
        let hash = Sha256::digest(self.0.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash[..32]);
        SecP256Fr::from_le_bytes_mod_order(&bytes)
    }
}

/// A [BBSPresentation] is a proof of knowledge of the [VerifiedCredential]. It contains
/// a proof that the presentation has been signed by the [Issuer], and can be
/// verified by the certificate of the [Issuer].
#[derive(Clone, CanonicalSerialize, Debug)]
pub struct BBSPresentation {
    /// The proof of knowledge of the [VerifiedCredential], which can be verified
    /// using the certificate of the [Issuer].
    proof: PoKOfSignatureG1Proof<Bls12_381>,
    /// Revealed messages of the [VerifiedCredential], which will prove that the
    /// [BBSPresentation::message_strings] are part of the credential.
    revealed: BTreeMap<usize, BlsFr>,
    /// Strings used to hash to the messages being _revealed_.
    message_strings: BTreeMap<usize, String>,
    /// Commitment to the x-coordinate of the public key
    commitment_pub_x: PublicCommitment,
    /// Commitment to the y-coordinate of the public key
    commitment_pub_y: PublicCommitment,
}

impl BBSPresentation {
    pub fn new(
        setup: &mut PublicSetup,
        vc: &VerifiedCredential,
        message: VerifierMessage,
        reveal: Vec<usize>,
    ) -> Self {
        let mut messages_and_blindings = vec![
            MessageOrBlinding::BlindMessageRandomly(&vc.messages[0]),
            MessageOrBlinding::BlindMessageRandomly(&vc.messages[1]),
        ];

        // Add the first- or last-name, depending on the request.
        let mut message_strings = BTreeMap::new();
        let mut revealed = BTreeMap::new();
        for idx in [
            VerifiedCredential::FIELD_FIRSTNAME,
            VerifiedCredential::FIELD_LASTNAME,
            VerifiedCredential::FIELD_DATEOFBIRTH,
        ] {
            let msg = &vc.messages[idx];
            if reveal.contains(&idx) {
                messages_and_blindings.push(MessageOrBlinding::RevealMessage(msg));
                message_strings.insert(idx, vc.message_strings[&idx].clone());
                revealed.insert(idx, msg.clone());
            } else {
                messages_and_blindings.push(MessageOrBlinding::BlindMessageRandomly(msg));
            }
        }

        let proof = PoKOfSignatureG1Protocol::init(
            &mut setup.rng,
            &vc.signature,
            &setup.sig_params_g1,
            messages_and_blindings,
        )
        .unwrap()
        .gen_proof(&(&message).into())
        .unwrap();

        Self {
            proof,
            revealed,
            message_strings,
            commitment_pub_x: PublicCommitment::from_message(
                setup,
                &vc.messages[VerifiedCredential::FIELD_PUB_X],
            ),
            commitment_pub_y: PublicCommitment::from_message(
                setup,
                &vc.messages[VerifiedCredential::FIELD_PUB_Y],
            ),
        }
    }

    /// Make sure the BBSPresentation is closed - a better version would use the
    /// `*Protocol` and `*Proof` like in the rest of docknetwork/crypto library.
    pub fn assert_closed(&self) {
        self.commitment_pub_x.assert_closed();
        self.commitment_pub_y.assert_closed();
    }

    /// Close the commitments by removing the random values.
    pub fn close(self) -> Self {
        Self {
            proof: self.proof,
            revealed: self.revealed,
            message_strings: self.message_strings,
            commitment_pub_x: self.commitment_pub_x.close(),
            commitment_pub_y: self.commitment_pub_y.close(),
        }
    }

    /// Verify that:
    /// - the signature can be verified by the certificate
    /// - the signature matches the messages
    /// - the message_strings match the messages
    /// - the BBS signature matches the commitment_pub
    pub fn verify(
        &self,
        setup: PublicSetup,
        issuer_certificate: PublicKeyG2<Bls12_381>,
        verifier_message: &BlsFr,
    ) -> Result<(), BBSPlusError> {
        // Is the BBS proof valid?
        self.proof.verify(
            &self.revealed,
            verifier_message,
            issuer_certificate,
            setup.sig_params_g1.clone(),
        )?;

        // Check all the revealed message strings to match the BBS messages.
        for (rev_id, bbs_msg) in &self.revealed {
            match self.message_strings.get(rev_id) {
                Some(msg_str) => {
                    if bbs_msg != &(&VerifierMessage(msg_str.clone())).into() {
                        return Err(BBSPlusError::InvalidSignature);
                    }
                }
                None => return Err(BBSPlusError::IncorrectNoOfShares(*rev_id, 0)),
            }
        }

        Ok(())
    }

    /// Returns the optional message_string at position `idx`.
    /// If `Verify` has not been called, this is not reliable!
    pub fn message_string(&self, idx: usize) -> Option<String> {
        self.message_strings.get(&idx).cloned()
    }

    /// Returns the size of the BBS proof.
    pub fn get_sizes(&self) -> HashMap<&str, usize> {
        HashMap::from([("proof_bbs", self.proof.compressed_size())])
    }

    /// Returns the JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Error while serializing to json")
    }
}

impl CanonicalSerialize for PublicCommitment {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        mode: Compress,
    ) -> Result<(), SerializationError> {
        match self {
            PublicCommitment::Open(fp, affine) => {
                fp.serialize_with_mode(&mut writer, mode)?;
                affine.serialize_with_mode(&mut writer, mode)?;
            }
            PublicCommitment::Closed(affine) => affine.serialize_with_mode(&mut writer, mode)?,
        }
        Ok(())
    }

    fn serialized_size(&self, mode: Compress) -> usize {
        match self {
            PublicCommitment::Open(fp, affine) => {
                fp.serialized_size(mode) + affine.serialized_size(mode)
            }
            PublicCommitment::Closed(affine) => affine.serialized_size(mode),
        }
    }
}

/// Use an enum to show that the commitments can be open, including the random value,
/// or closed, which is secure.
#[derive(Clone, Debug)]
pub enum PublicCommitment {
    /// An Open commitment includes the random value, which is the [BlsFr] here.
    /// It should never be sent to an untrusted party, as they can get some knowledge
    /// of the original value with it.
    Open(BlsFr, BlsG1Affine),
    /// A Closed commitment is stripped of its random value and can safely be shared
    /// with untrusted parties.
    Closed(BlsG1Affine),
}

impl PublicCommitment {
    /// Create a new commitment from a scalar. This returns an Open commitment,
    /// including the random value.
    pub fn from_message(setup: &mut PublicSetup, message: &BlsFr) -> Self {
        let randomness = BlsFr::rand(&mut setup.rng);
        Self::Open(randomness, setup.comm_key_bls.commit(message, &randomness))
    }

    /// Close this commitment by discarding the random value.
    /// For security, this consumes the [PublicCommitment].
    pub fn close(self) -> Self {
        match self {
            PublicCommitment::Open(_, affine) => PublicCommitment::Closed(affine),
            _ => self,
        }
    }

    /// Returns the random value of this commitment.
    /// If the commitment is closed, it panics.
    pub fn rand(&self) -> BlsFr {
        match self {
            PublicCommitment::Open(fp, _) => fp.clone(),
            _ => panic!("No random value in closed commitment"),
        }
    }

    /// Returns the affine, public, value of this commitment, which is always available.
    pub fn affine(&self) -> BlsG1Affine {
        match self {
            PublicCommitment::Open(_, affine) => affine.clone(),
            PublicCommitment::Closed(affine) => affine.clone(),
        }
    }

    /// Make sure the commitment has been closed.
    pub fn assert_closed(&self) {
        if let Self::Open(_, _) = self {
            panic!("PublicCommitment is open and leaks random value!");
        }
    }
}

/// Thanks go to ChatGPT for this code...
impl Serialize for BBSPresentation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Helper to serialize ark-serialize types as base64
        fn serialize_ark<T: CanonicalSerialize>(t: &T) -> String {
            let mut buf = Vec::new();
            t.serialize_compressed(&mut buf).unwrap();
            BASE64_STANDARD.encode(buf)
        }

        // Serialize revealed map: idx -> base64(BlsFr)
        let revealed: BTreeMap<usize, String> = self
            .revealed
            .iter()
            .map(|(k, v)| (*k, serialize_ark(v)))
            .collect();

        // Serialize message_strings as is
        let message_strings = &self.message_strings;

        // Serialize commitments
        fn serialize_commitment(c: &PublicCommitment) -> serde_json::Value {
            match c {
                PublicCommitment::Open(rand, affine) => {
                    serde_json::json!({
                        "type": "open",
                        "rand": serialize_ark(rand),
                        "affine": serialize_ark(affine),
                    })
                }
                PublicCommitment::Closed(affine) => {
                    serde_json::json!({
                        "type": "closed",
                        "affine": serialize_ark(affine),
                    })
                }
            }
        }

        // Serialize PoK proof
        let proof_bytes = {
            let mut buf = Vec::new();
            self.proof.serialize_compressed(&mut buf).unwrap();
            BASE64_STANDARD.encode(buf)
        };

        let mut state = serializer.serialize_struct("BBSPresentation", 5)?;
        state.serialize_field("proof", &proof_bytes)?;
        state.serialize_field("revealed", &revealed)?;
        state.serialize_field("message_strings", message_strings)?;
        state.serialize_field(
            "commitment_pub_x",
            &serialize_commitment(&self.commitment_pub_x),
        )?;
        state.serialize_field(
            "commitment_pub_y",
            &serialize_commitment(&self.commitment_pub_y),
        )?;
        state.end()
    }
}

/// Thanks to ChatGPT for this serialization stub.
impl Serialize for PublicSetup {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PublicSetup", 5)?;
        state.serialize_field("sig_params_g1", &self.sig_params_g1)?;
        // Serialize bpp_setup_params as base64-encoded compressed bytes
        let mut bpp_bytes = Vec::new();
        self.bpp_setup_params
            .serialize_compressed(&mut bpp_bytes)
            .unwrap();
        let bpp_base64 = BASE64_STANDARD.encode(bpp_bytes);
        state.serialize_field("bpp_setup_params", &bpp_base64)?;
        state.serialize_field("comm_key_tom", &self.comm_key_tom)?;
        state.serialize_field("comm_key_secp", &self.comm_key_secp)?;
        state.serialize_field("comm_key_bls", &self.comm_key_bls)?;
        state.end()
    }
}

/// An [ECDSAProof] links the ECDSA signature from the [SecureElement] to the [BBSPresentation::close]
/// messages in zero-knowledge.
/// The commitments are randomized representations of the holder's public key.
/// The proofs link these commitments to the message to be signed, and between each other.
#[derive(Clone)]
pub struct ECDSAProof {
    /// A commitment of the public key of the holder to the Tom256 curve.
    comm_pk: PointCommitment<Tom256Config>,
    /// A proof that [ECDSAProof::comm_pk] can be used to verify the `message` of the verifier.
    proof: PoKEcdsaSigCommittedPublicKey<{ ECDSAProof::NUM_REPS_SCALAR_MULT }>,
    /// A proof that the x value of the public key of the holder is the same as [BBSPresentation::commitment_pub_x]
    proof_eq_pk_x: ProofEqDL,
    /// A proof that the y value of the public key of the holder is the same as [BBSPresentation::commitment_pub_y]
    proof_eq_pk_y: ProofEqDL,
    /// A proof that the commitments used in the above proofs is equal to the x- and y-
    /// coordinates of the public key stored in the BBS proof.
    proof_eq_pk_bbs: Proof<Bls12_381>,
}

/// Parametrization of the discreet log equality proof.
type ProofEqDL = ProofLargeWitness<
    Tom256Affine,
    BlsG1Affine,
    { PublicSetup::NUM_CHUNKS },
    { PublicSetup::WITNESS_BIT_SIZE },
    { PublicSetup::CHALLENGE_BIT_SIZE },
    { PublicSetup::ABORT_PARAM },
    { PublicSetup::RESPONSE_BYTE_SIZE },
    { PublicSetup::NUM_REPS },
>;

impl ECDSAProof {
    const NUM_REPS_SCALAR_MULT: usize = 128;

    /// Create a new proof that the public key stored in a commitment can be used
    /// to verify a signature.
    /// This follows the excellent work done by Lovesh in
    /// [docknetwork/crypto](https://github.com/docknetwork/crypto/blob/main/equality_across_groups/src/pok_ecdsa_pubkey.rs#L462).
    pub fn new(
        setup: &mut PublicSetup,
        holder_pub: &SecP256Affine,
        vc: &VerifiedCredential,
        bbs_presentation: &BBSPresentation,
        ecdsa_signature: &ecdsa::Signature,
        verifier_message: &VerifierMessage,
    ) -> Self {
        // Commit to ECDSA public key on Tom-256 curve
        let comm_pk =
            PointCommitmentWithOpening::new(&mut setup.rng, &holder_pub, &setup.comm_key_tom)
                .unwrap();

        let transformed_sig = TransformedEcdsaSig::new(
            &ecdsa_signature,
            verifier_message.into(),
            holder_pub.clone(),
        )
        .unwrap();
        transformed_sig
            .verify_prehashed(verifier_message.into(), holder_pub.clone())
            .unwrap();

        // Create the transcript which will be used for the challenge.
        // All variables which can be chosen by the prover must find their way into the transcript,
        // else the prover can have an advantage in creating a wrong proof.
        let mut prover_transcript = new_merlin_transcript(b"test");
        setup.append_transcript(&mut prover_transcript);
        Self::append_transcript(
            &mut prover_transcript,
            &comm_pk.comm,
            &bbs_presentation,
            &verifier_message.into(),
        );

        // Create a protocol to prove that the `transformed_sig` on the `verifier_message`
        // can be verified using the commitment `comm_pk`.
        let protocol =
            PoKEcdsaSigCommittedPublicKeyProtocol::<{ ECDSAProof::NUM_REPS_SCALAR_MULT }>::init(
                &mut setup.rng,
                transformed_sig,
                verifier_message.into(),
                holder_pub.clone(),
                comm_pk.clone(),
                &setup.comm_key_secp,
                &setup.comm_key_tom,
            )
            .unwrap();
        protocol
            .challenge_contribution(&mut prover_transcript)
            .unwrap();
        let challenge_prover = prover_transcript.challenge_scalar(b"challenge");
        let proof = protocol.gen_proof(&challenge_prover);

        // Proof that the x coordinate is same in both Tom-256 and BLS12-381 commitments
        let proof_eq_pk_x = ProofEqDL::new(
            &mut setup.rng,
            &comm_pk.x,
            comm_pk.r_x,
            bbs_presentation.commitment_pub_x.rand(),
            &setup.comm_key_tom,
            &setup.comm_key_bls,
            PublicSetup::BPP_BASE,
            setup.bpp_setup_params.clone(),
            &mut prover_transcript,
        )
        .unwrap();

        // Proof that the y coordinate is same in both Tom-256 and BLS12-381 commitments
        let proof_eq_pk_y = ProofEqDL::new(
            &mut setup.rng,
            &comm_pk.y,
            comm_pk.r_y,
            bbs_presentation.commitment_pub_y.rand(),
            &setup.comm_key_tom,
            &setup.comm_key_bls,
            PublicSetup::BPP_BASE,
            setup.bpp_setup_params.clone(),
            &mut prover_transcript,
        )
        .unwrap();

        // Proof that the commitments to x- and y- coordinates correspond to the BBS signature.
        let mut statements = Statements::<Bls12_381>::new();
        statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![setup.comm_key_bls.g, setup.comm_key_bls.h],
            bbs_presentation.commitment_pub_x.affine(),
        ));
        statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![setup.comm_key_bls.g, setup.comm_key_bls.h],
            bbs_presentation.commitment_pub_y.affine(),
        ));
        statements.add(
            PoKBBSSignatureG1Prover::<Bls12_381>::new_statement_from_params(
                setup.sig_params_g1.clone(),
                BTreeMap::new(),
            ),
        );

        let mut meta_statements = MetaStatements::new();
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
            vec![(0, 0), (2, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        )));
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
            vec![(1, 0), (2, 1)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        )));

        let mut witnesses = Witnesses::new();
        witnesses.add(Witness::PedersenCommitment(vec![
            vc.messages[0].clone(),
            bbs_presentation.commitment_pub_x.rand(),
        ]));
        witnesses.add(Witness::PedersenCommitment(vec![
            vc.messages[1].clone(),
            bbs_presentation.commitment_pub_y.rand(),
        ]));
        witnesses.add(PoKBBSSignatureG1::new_as_witness(
            vc.signature.clone(),
            BTreeMap::from([
                (0, vc.messages[0]),
                (1, vc.messages[1]),
                (2, vc.messages[2]),
                (3, vc.messages[3]),
                (4, vc.messages[4]),
            ]),
        ));

        let context = Some(b"test".to_vec());
        let proof_spec = ProofSpec::new(
            statements.clone(),
            meta_statements.clone(),
            vec![],
            context.clone(),
        );
        proof_spec.validate().unwrap();

        let nonce_eq_pk = Some(b"test nonce".to_vec());
        let proof_eq_pk_bbs = Proof::new::<StdRng, Blake2b512>(
            &mut setup.rng,
            proof_spec.clone(),
            witnesses.clone(),
            nonce_eq_pk.clone(),
            Default::default(),
        )
        .unwrap()
        .0;

        Self {
            comm_pk: comm_pk.comm,
            proof,
            proof_eq_pk_x,
            proof_eq_pk_y,
            proof_eq_pk_bbs,
        }
    }

    /// Verifies that the commitments to the signature and the public key of the holder
    /// verify the `message` from the verifier. The [BBSPresentation] is used for the commitments
    /// to the holder's public key.
    pub fn verify(
        &self,
        mut setup: PublicSetup,
        message: SecP256Fr,
        presentation: &BBSPresentation,
        issuer_pub: &PublicKeyG2<Bls12_381>,
    ) {
        presentation.assert_closed();
        let mut verifier_transcript = new_merlin_transcript(b"test");
        setup.append_transcript(&mut verifier_transcript);
        Self::append_transcript(
            &mut verifier_transcript,
            &self.comm_pk,
            presentation,
            &message,
        );
        self.proof
            .challenge_contribution(&mut verifier_transcript)
            .unwrap();

        let challenge_verifier = verifier_transcript.challenge_scalar(b"challenge");

        // Exercise for the reader: verify_using_randomized_mult_checker can be used to make it much faster.
        // See [docknetwork/crypto](https://github.com/docknetwork/crypto/blob/main/equality_across_groups/src/pok_ecdsa_pubkey.rs#L434)
        self.proof
            .verify(
                message,
                &self.comm_pk,
                &challenge_verifier,
                &setup.comm_key_secp,
                &setup.comm_key_tom,
            )
            .expect("ECDSA proof failed");

        // Verify the proof for the equality between the Tom-256 commitment and the BBS-commitment:
        // x-coordinate
        self.proof_eq_pk_x
            .verify(
                &self.comm_pk.x,
                &presentation.commitment_pub_x.affine(),
                &setup.comm_key_tom,
                &setup.comm_key_bls,
                &setup.bpp_setup_params,
                &mut verifier_transcript,
            )
            .expect("DlEQ proof for x position failed");

        // Verify the proof for the equality between the Tom-256 commitment and the BBS-commitment:
        // y-coordinate
        self.proof_eq_pk_y
            .verify(
                &self.comm_pk.y,
                &presentation.commitment_pub_y.affine(),
                &setup.comm_key_tom,
                &setup.comm_key_bls,
                &setup.bpp_setup_params,
                &mut verifier_transcript,
            )
            .expect("DlEQ proff for y position failed");

        // And verify that the given commitments equal the coordinates of the public key
        // in the BBS signature.
        let mut verifier_statements = Statements::<Bls12_381>::new();
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![setup.comm_key_bls.g, setup.comm_key_bls.h],
            presentation.commitment_pub_x.affine(),
        ));
        verifier_statements.add(PedersenCommitmentStmt::new_statement_from_params(
            vec![setup.comm_key_bls.g, setup.comm_key_bls.h],
            presentation.commitment_pub_y.affine(),
        ));
        verifier_statements.add(PoKBBSSignatureG1Verifier::new_statement_from_params(
            setup.sig_params_g1.clone(),
            issuer_pub.clone(),
            BTreeMap::new(),
        ));

        let mut meta_statements = MetaStatements::new();
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
            vec![(0, 0), (2, 0)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        )));
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
            vec![(1, 0), (2, 1)]
                .into_iter()
                .collect::<BTreeSet<WitnessRef>>(),
        )));

        let context = Some(b"test".to_vec());
        let verifier_proof_spec = ProofSpec::new(
            verifier_statements.clone(),
            meta_statements.clone(),
            vec![],
            context.clone(),
        );
        verifier_proof_spec.validate().unwrap();

        let nonce_eq_pk = Some(b"test nonce".to_vec());
        self.proof_eq_pk_bbs
            .clone()
            .verify::<StdRng, Blake2b512>(
                &mut setup.rng,
                verifier_proof_spec,
                nonce_eq_pk.clone(),
                Default::default(),
            )
            .expect("Verify Point Equality Proof");
    }

    /// Returns the sizes of the different proofs.
    pub fn get_sizes(&self) -> HashMap<&str, usize> {
        HashMap::from([
            ("proof_add", self.proof.proof_add.compressed_size()),
            ("proof_scalar", self.proof.proof_minus_zR.compressed_size()),
            ("proof_eqdl_x", self.proof_eq_pk_x.compressed_size()),
            ("proof_eqdl_y", self.proof_eq_pk_y.compressed_size()),
            ("proof_eq_comm_bbs", self.proof_eq_pk_bbs.compressed_size()),
        ])
    }

    /// Returns the json string of the structure.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("While serializing to JSON")
    }

    // Put the relevant entries in the transcript.
    fn append_transcript<T: Transcript + Clone + Write>(
        pt: &mut T,
        comm_pk: &PointCommitment<Tom256Config>,
        presentation: &BBSPresentation,
        message: &SecP256Fr,
    ) {
        pt.append(b"comm_pk", comm_pk);
        pt.append(b"bls_comm_pk_x", &presentation.commitment_pub_x.affine());
        pt.append(b"bls_comm_pk_y", &presentation.commitment_pub_y.affine());
        pt.append(b"message", message);
    }
}

/// Thanks to ChatGPT for this serialization stub.
impl Serialize for ECDSAProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Helper to serialize ark-serialize types as base64
        fn serialize_ark<T: CanonicalSerialize>(t: &T) -> String {
            let mut buf = Vec::new();
            t.serialize_compressed(&mut buf).unwrap();
            BASE64_STANDARD.encode(buf)
        }

        let comm_pk_bytes = serialize_ark(&self.comm_pk);
        let proof_bytes = serialize_ark(&self.proof);
        let proof_eq_pk_x_bytes = serialize_ark(&self.proof_eq_pk_x);
        let proof_eq_pk_y_bytes = serialize_ark(&self.proof_eq_pk_y);

        let mut state = serializer.serialize_struct("ECDSAProof", 4)?;
        state.serialize_field("comm_pk", &comm_pk_bytes)?;
        state.serialize_field("proof", &proof_bytes)?;
        state.serialize_field("proof_eq_pk_x", &proof_eq_pk_x_bytes)?;
        state.serialize_field("proof_eq_pk_y", &proof_eq_pk_y_bytes)?;
        state.end()
    }
}

/// An [AgeProof] proves that the holder's date of birth is within a given bound,
/// proving they are at least a certain age without revealing the exact date.
pub struct AgeProof {
    proof: Proof<Bls12_381>,
}

impl AgeProof {
    /// Create a new age proof proving that `date_of_birth < max_dob`.
    /// This proves the holder was born before `max_dob`, i.e., they are at least
    /// `(now - max_dob)` years old.
    pub fn new(
        setup: &mut PublicSetup,
        vc: &VerifiedCredential,
        _issuer_pk: &PublicKeyG2<Bls12_381>,
        max_dob: u64,
    ) -> Self {
        let statements = Self::prover_statements(setup, max_dob);
        let meta_statements = Self::meta_statements();

        // Create witnesses
        let mut witnesses = Witnesses::new();
        witnesses.add(PoKBBSSignatureG1::new_as_witness(
            vc.signature.clone(),
            BTreeMap::from([
                (0, vc.messages[0]),
                (1, vc.messages[1]),
                (2, vc.messages[2]),
                (3, vc.messages[3]),
                (4, vc.messages[4]),
            ]),
        ));
        witnesses.add(Witness::BoundCheckBpp(
            vc.message_u64[&VerifiedCredential::FIELD_DATEOFBIRTH].into(),
        ));

        let proof_spec = ProofSpec::new(statements, meta_statements, vec![], None);
        proof_spec.validate().expect("Invalid proof spec");

        let proof = Proof::new::<StdRng, Blake2b512>(
            &mut setup.rng,
            proof_spec,
            witnesses,
            None,
            Default::default(),
        )
        .expect("Failed to create age proof")
        .0;

        Self { proof }
    }

    /// Verify that the age proof is valid for the given `max_dob` bound.
    pub fn verify(&self, setup: &PublicSetup, issuer_pk: &PublicKeyG2<Bls12_381>, max_dob: u64) {
        let statements = Self::verifier_statements(setup, issuer_pk, max_dob);
        let meta_statements = Self::meta_statements();

        let proof_spec = ProofSpec::new(statements, meta_statements, vec![], None);

        self.proof
            .clone()
            .verify::<StdRng, Blake2b512>(
                &mut StdRng::seed_from_u64(0),
                proof_spec,
                None,
                Default::default(),
            )
            .expect("Age proof verification failed");
    }

    /// Create prover statements for age proof.
    fn prover_statements(setup: &PublicSetup, max_dob: u64) -> Statements<Bls12_381> {
        let mut statements = Statements::<Bls12_381>::new();
        // Statement 0: BBS signature proof of knowledge
        statements.add(
            PoKBBSSignatureG1Prover::<Bls12_381>::new_statement_from_params(
                setup.sig_params_g1.clone(),
                BTreeMap::new(), // No revealed messages
            ),
        );
        // Statement 1: Bound check (0 <= dob < max_dob)
        statements.add(
            BoundCheckBpp::new_statement_from_params(
                0,
                max_dob,
                setup.bpp_setup_params_bls.clone(),
            )
            .expect("Failed to create BoundCheckBpp statement"),
        );
        statements
    }

    /// Create verifier statements for age proof.
    fn verifier_statements(
        setup: &PublicSetup,
        issuer_pk: &PublicKeyG2<Bls12_381>,
        max_dob: u64,
    ) -> Statements<Bls12_381> {
        let mut statements = Statements::<Bls12_381>::new();
        // Statement 0: BBS signature verification
        statements.add(PoKBBSSignatureG1Verifier::new_statement_from_params(
            setup.sig_params_g1.clone(),
            issuer_pk.clone(),
            BTreeMap::new(),
        ));
        // Statement 1: Bound check (0 <= dob < max_dob)
        statements.add(
            BoundCheckBpp::new_statement_from_params(
                0,
                max_dob,
                setup.bpp_setup_params_bls.clone(),
            )
            .expect("Failed to create BoundCheckBpp statement"),
        );
        statements
    }

    /// Create meta statements linking BBS message to bound check witness.
    fn meta_statements() -> MetaStatements {
        let mut meta_statements = MetaStatements::new();
        // Link BBS message[4] (DOB) to bound check witness
        meta_statements.add(MetaStatement::WitnessEquality(EqualWitnesses(
            vec![
                (0, VerifiedCredential::FIELD_DATEOFBIRTH), // BBS sig msg at index 4
                (1, 0),                                     // Bound check witness
            ]
            .into_iter()
            .collect::<BTreeSet<WitnessRef>>(),
        )));
        meta_statements
    }
}
