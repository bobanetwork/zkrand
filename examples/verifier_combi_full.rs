use ark_std::{end_timer, start_timer};
use halo2_solidity_verifier::{
    compile_solidity, encode_calldata, BatchOpenScheme::Bdfg21, Evm, Keccak256Transcript,
    SolidityGenerator,
};
use halo2wrong::curves::bn256::{Bn256, Fr as BnScalar, G1Affine as BnG1};
use halo2wrong::curves::group::Curve;
use halo2wrong::curves::grumpkin::G1Affine as GkG1;
use halo2wrong::halo2::plonk::{create_proof, verify_proof, Circuit, ProvingKey};
use halo2wrong::halo2::poly::commitment::ParamsProver;
use halo2wrong::halo2::poly::kzg::commitment::{ParamsKZG, ParamsVerifierKZG};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, File};
use std::io::Write;
use zkdvrf::dkg::{DkgConfig, PartialEval};
use zkdvrf::{
    combine_partial_evaluations, dkg_global_public_params, hash_to_curve_bn, load_or_create_params,
    load_or_create_pk, DkgGlobalPubParams, DkgMemberParams, MemberKey, PseudoRandom, EVAL_PREFIX,
};

// cargo run --release --features="g2chip" --example verifier_combi_full

const DIR_GENERATED: &str = "./contracts/data";

fn mock_members(dkg_config: &DkgConfig, mut rng: impl RngCore) -> (Vec<GkG1>, Vec<MemberKey>) {
    let mut members = vec![];
    let mut pks = vec![];
    for _ in 0..dkg_config.number_of_members() {
        let member = MemberKey::random(&mut rng);
        pks.push(member.public_key());
        members.push(member);
    }
    (pks, members)
}

fn save_solidity(name: impl AsRef<str>, solidity: &str) {
    create_dir_all(DIR_GENERATED).unwrap();
    File::create(format!("{DIR_GENERATED}/{}", name.as_ref()))
        .unwrap()
        .write_all(solidity.as_bytes())
        .unwrap();
}

fn save_proof(proof: &[u8]) {
    let path = format!("{DIR_GENERATED}/proof.dat");
    let mut file = File::create(path).unwrap();

    // Write the bytes to the file
    file.write_all(proof).unwrap();
}

fn save_instance(instance: &[BnScalar]) {
    let path = format!("{DIR_GENERATED}/instance.json");
    let mut file = File::create(path).unwrap();
    let instance_bytes: Vec<_> = instance.iter().map(|x| x.to_bytes()).collect();
    // Write the bytes to the file
    let serialized = serde_json::to_string(&instance_bytes).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();
}

fn save_instances(instances: &[Vec<BnScalar>]) {
    let path = format!("{DIR_GENERATED}/all_instances.json");
    let mut file = File::create(path).unwrap();
    let mut instances_bytes = vec![];
    for instance in instances.iter() {
        let bytes: Vec<_> = instance.iter().map(|x| x.to_bytes()).collect();
        instances_bytes.push(bytes);
    }
    // Write the bytes to the file
    let serialized = serde_json::to_string(&instances_bytes).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();
}

fn save_params(gpp: &DkgGlobalPubParams) {
    let path = format!("{DIR_GENERATED}/g2a.json");
    let mut file = File::create(path).unwrap();
    // only save g2a
    let x0 = gpp.g2a.x.c0.to_bytes();
    let x1 = gpp.g2a.x.c1.to_bytes();
    let y0 = gpp.g2a.y.c0.to_bytes();
    let y1 = gpp.g2a.y.c1.to_bytes();
    // Write the bytes to the file
    let serialized = serde_json::to_string(&[x0, x1, y0, y1]).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();
}

type Scalar = [u8; 32];
type Base = [u8; 32];

#[derive(Debug, Serialize, Deserialize)]
struct PointG1 {
    #[serde(rename = "X")]
    x: [u8; 32],
    #[serde(rename = "Y")]
    y: [u8; 32],
}

impl From<&BnG1> for PointG1 {
    fn from(p: &BnG1) -> Self {
        PointG1 {
            x: p.x.to_bytes(),
            y: p.y.to_bytes(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Eval {
    value: [Base; 2],
    proof: [Scalar; 2],
    vk: [Base; 2],
    hash: [Base; 2],
}

fn save_eval(sigma: &PartialEval, vk: &BnG1, hash: &BnG1) {
    let value = [sigma.value.x.to_bytes(), sigma.value.y.to_bytes()];
    let proof = [sigma.proof.0.to_bytes(), sigma.proof.1.to_bytes()];
    let vk = [vk.x.to_bytes(), vk.y.to_bytes()];
    let hash = [hash.x.to_bytes(), hash.y.to_bytes()];

    let eval = Eval {
        value,
        proof,
        vk,
        hash,
    };
    let serialized = serde_json::to_string(&eval).unwrap();
    let path = format!("{DIR_GENERATED}/eval.json");
    let mut file = File::create(path).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();
}

fn save_pseudo(pseudo_random: &PseudoRandom) {
    let path = format!("{DIR_GENERATED}/pseudo.json");
    let mut file = File::create(path).unwrap();
    // only store the proof
    let proof = pseudo_random.proof();
    let x = proof.x.to_bytes();
    let y = proof.y.to_bytes();
    let serialized = serde_json::to_string(&[x, y]).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();
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

    let start = start_timer!(|| format!("verify proof"));
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
    end_timer!(start);

    proof
}

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    let (threshold, number_of_members, degree): (usize, usize, usize) = (3, 5, 18);
    const PROVE: bool = false;

    let dkg_config = DkgConfig::new(threshold, number_of_members).unwrap();
    let (pks, members) = mock_members(&dkg_config, &mut rng);
    // member index from 1..n
    let dkgs: Vec<_> = (0..number_of_members)
        .map(|_| DkgMemberParams::new(dkg_config, pks.clone(), &mut rng).unwrap())
        .collect();
    let dkgs_pub: Vec<_> = dkgs.iter().map(|dkg| dkg.member_public_params()).collect();

    // compute global public parameters
    let pp = dkg_global_public_params(&dkgs_pub);
    save_params(&pp);

    // all the instances
    let instances: Vec<_> = dkgs.iter().map(|dkg| dkg.instance()[0].clone()).collect();
    save_instances(&instances);

    if PROVE {
        let circuit = dkgs[0].circuit(&mut rng);
        let instance0 = instances[0].clone();
        let num_instances = instance0.len();
        println!("num instances {:?}", num_instances);

        let start = start_timer!(|| format!("kzg load or setup params with degree {}", degree));
        let params_dir = "./kzg_params";
        let general_params = load_or_create_params(params_dir, degree).unwrap();
        let _verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
        end_timer!(start);

        let start =
            start_timer!(|| format!("kzg load or setup proving keys with degree {}", degree));
        let pk = load_or_create_pk(dkg_config, params_dir, &general_params, degree).unwrap();
        let vk = pk.get_vk();
        end_timer!(start);

        let start = start_timer!(|| "create solidity contracts");
        let generator = SolidityGenerator::new(&general_params, vk, Bdfg21, num_instances);
        let verifier_solidity = generator.render().unwrap();
        let contract_name = format!("Halo2Verifier-{}-{}.sol", threshold, number_of_members);
        #[cfg(feature = "g2chip")]
        let contract_name = format!("Halo2Verifier-{}-{}-g2.sol", threshold, number_of_members);
        save_solidity(contract_name, &verifier_solidity);
        end_timer!(start);

        let start = start_timer!(|| "compile and deploy solidity contracts");
        let verifier_creation_code = compile_solidity(&verifier_solidity);
        println!(
            "verifier creation code size: {:?}",
            verifier_creation_code.len()
        );

        let mut evm = Evm::default();
        let verifier_address = evm.create(verifier_creation_code);
        end_timer!(start);

        let calldata = {
            let start = start_timer!(|| "create and verify proof");
            let proof = create_proof_checked(&general_params, &pk, circuit, &instance0, &mut rng);
            end_timer!(start);
            println!("size of proof {:?}", proof.len());
            // write proof to file
            save_proof(&proof);
            save_instance(&instance0);
            encode_calldata(None, &proof, &instance0)
        };
        println!("calldata size {:?}", calldata.len());
        let start = start_timer!(|| "evm call");
        let (gas_cost, output) = evm.call(verifier_address, calldata);
        end_timer!(start);
        assert_eq!(output, [vec![0; 31], vec![1]].concat());
        println!("Gas cost of verifying dkg circuit proof with 2^{degree} rows: {gas_cost}");
    }

    // each member decrypt to obtain their own shares
    let mut shares = vec![];
    for i in 0..number_of_members {
        assert_eq!(members[i].public_key(), pks[i]);
        let share = members[i]
            .dkg_share_key(&dkg_config, i + 1, &dkgs_pub)
            .unwrap();
        share.verify(&dkg_config, &pp.verify_keys).unwrap();

        shares.push(share);
    }

    // each member performs partial evaluation
    let input = b"first random";
    let hasher = hash_to_curve_bn(EVAL_PREFIX);
    let hash: BnG1 = hasher(input).to_affine();

    let mut sigmas = vec![];
    for i in 0..number_of_members {
        let sigma = shares[i].evaluate(input, &mut rng);
        sigma
            .verify(&dkg_config, input, &pp.verify_keys[i])
            .unwrap();
        sigmas.push(sigma);
    }

    save_eval(&sigmas[0], &pp.verify_keys[0], &hash);

    // combine partial evaluations to obtain final random
    let v = combine_partial_evaluations(&dkg_config, &sigmas[0..threshold]).unwrap();
    save_pseudo(&v);
    v.verify(input, &pp.g2a).unwrap();
}
