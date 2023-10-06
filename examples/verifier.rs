use ark_std::{end_timer, start_timer};
use halo2_solidity_verifier::{
    compile_solidity, encode_calldata, BatchOpenScheme::Bdfg21, Evm, Keccak256Transcript,
    SolidityGenerator,
};
use halo2wrong::curves::bn256::{Bn256, Fr as BnScalar, G1Affine as BnG1};
use halo2wrong::curves::grumpkin::G1Affine as GkG1;
use halo2wrong::halo2::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey,
};
use halo2wrong::halo2::poly::commitment::ParamsProver;
use halo2wrong::halo2::poly::kzg::commitment::{ParamsKZG, ParamsVerifierKZG};
use halo2wrong::halo2::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2wrong::halo2::poly::kzg::strategy::SingleStrategy;
use halo2wrong::halo2::transcript::TranscriptWriterBuffer;
use rand_core::{OsRng, RngCore};
use std::fs::{create_dir_all, File};
use std::io::Write;
use zkdvrf::{
    load_or_create_params, load_or_create_pk, CircuitDkg, DkgMemberParams, MemberKey,
    DEFAULT_WINDOW_SIZE,
};

fn simulate_members<const NUMBER_OF_MEMBERS: usize>(
    mut rng: impl RngCore,
) -> (Vec<GkG1>, Vec<MemberKey>) {
    let mut members = vec![];
    let mut pks = vec![];
    for _ in 0..NUMBER_OF_MEMBERS {
        let member = MemberKey::new(&mut rng);
        pks.push(member.get_public_key());
        members.push(member);
    }
    (pks, members)
}

fn save_solidity(name: impl AsRef<str>, solidity: &str) {
    const DIR_GENERATED: &str = "./contracts_generated";

    create_dir_all(DIR_GENERATED).unwrap();
    File::create(format!("{DIR_GENERATED}/{}", name.as_ref()))
        .unwrap()
        .write_all(solidity.as_bytes())
        .unwrap();
}

fn create_proof_checked(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<BnG1>,
    circuit: impl Circuit<BnScalar>,
    instances: &[BnScalar],
    mut rng: impl RngCore,
) -> Vec<u8> {
    use halo2wrong::halo2::{
        poly::kzg::{
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::TranscriptWriterBuffer,
    };

    let proof = {
        let mut transcript = Keccak256Transcript::new(Vec::new());
        create_proof::<_, ProverSHPLONK<_>, _, _, _, _>(
            params,
            pk,
            &[circuit],
            &[&[instances]],
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let result = {
        let mut transcript = Keccak256Transcript::new(proof.as_slice());
        verify_proof::<_, VerifierSHPLONK<_>, _, _, SingleStrategy<_>>(
            params,
            pk.get_vk(),
            SingleStrategy::new(params),
            &[&[instances]],
            &mut transcript,
        )
    };
    assert!(result.is_ok());

    proof
}

fn main() {
    const THRESHOLD: usize = 3;
    const NUMBER_OF_MEMBERS: usize = 5;
    let degree = 18;

    // let mut rng = ChaCha20Rng::seed_from_u64(42);
    let mut rng = OsRng;
    let (mpks, _) = simulate_members::<NUMBER_OF_MEMBERS>(&mut rng);
    let dkg_params =
        DkgMemberParams::<THRESHOLD, NUMBER_OF_MEMBERS>::new(1, &mpks, &mut rng).unwrap();
    let circuit = dkg_params.circuit(&mut rng);
    let instance = dkg_params.instance();
    let num_instances = instance[0].len();

    let params_dir = "./kzg_params";
    let general_params = load_or_create_params(params_dir, degree).unwrap();
    let _verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();

    let pk = load_or_create_pk::<THRESHOLD, NUMBER_OF_MEMBERS>(params_dir, &general_params, degree)
        .unwrap();
    let vk = pk.get_vk();

    let generator = SolidityGenerator::new(&general_params, vk, Bdfg21, num_instances);
    let (verifier_solidity, vk_solidity) = generator.render_separately().unwrap();
    save_solidity("Halo2Verifier.sol", &verifier_solidity);
    save_solidity(format!("Halo2VerifyingKey-{degree}.sol"), &vk_solidity);

    let verifier_creation_code = compile_solidity(&verifier_solidity);
    let verifier_creation_code_size = verifier_creation_code.len();
    println!("Verifier creation code size: {verifier_creation_code_size}");

    let mut evm = Evm::default();
    let verifier_address = evm.create(verifier_creation_code);

    let calldata = {
        let proof = create_proof_checked(&general_params, &pk, circuit, &instance[0], &mut rng);
        println!("size of proof {:?}", proof.len());
        encode_calldata(Some(verifier_address.into()), &proof, &instance[0])
    };
    let (gas_cost, output) = evm.call(verifier_address, calldata);
    assert_eq!(output, [vec![0; 31], vec![1]].concat());
    println!("Gas cost of verifying standard Plonk with 2^{degree} rows: {gas_cost}");
}