use ark_std::{end_timer, start_timer};
use halo2_solidity_verifier::Keccak256Transcript;
use halo2wrong::curves::bn256::{Bn256, Fr as BnScalar, G1Affine as BnG1};
use halo2wrong::halo2::plonk::{create_proof, verify_proof, Circuit, ProvingKey, VerifyingKey};
use halo2wrong::halo2::poly::commitment::ParamsProver;
use halo2wrong::halo2::poly::kzg::commitment::ParamsKZG;
use halo2wrong::halo2::{
    poly::kzg::{
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::TranscriptWriterBuffer,
};
use rand_core::RngCore;

pub fn create_proof_checked(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<BnG1>,
    circuit: impl Circuit<BnScalar>,
    instance: &[BnScalar],
    mut rng: impl RngCore,
) -> Vec<u8> {
    let proof = {
        let mut transcript = Keccak256Transcript::new(Vec::new());
        create_proof::<_, ProverSHPLONK<_>, _, _, _, _>(
            params,
            pk,
            &[circuit],
            &[&[instance]],
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    verify_single(
        params.verifier_params(),
        pk.get_vk(),
        proof.as_slice(),
        instance,
    );

    proof
}

pub fn verify_single(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<BnG1>,
    proof: &[u8],
    instance: &[BnScalar],
) {
    let start = start_timer!(|| format!("verify proof"));
    let result = {
        let mut transcript = Keccak256Transcript::new(proof);
        verify_proof::<_, VerifierSHPLONK<_>, _, _, SingleStrategy<_>>(
            params,
            vk,
            SingleStrategy::new(params),
            &[&[instance]],
            &mut transcript,
        )
    };
    assert!(result.is_ok());
    end_timer!(start);
}
