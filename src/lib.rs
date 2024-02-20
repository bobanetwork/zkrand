pub mod dkg;
pub mod dkg_circuit;
mod ecc_chip;
mod error;
mod grumpkin_chip;
mod hash_to_curve;
mod hash_to_curve_evm;
mod poseidon;
mod utils;

pub use utils::{load_or_create_params, load_or_create_pk, load_or_create_vk};

use rand_core::RngCore;
use std::rc::Rc;

pub use halo2_ecc::integer::NUMBER_OF_LOOKUP_LIMBS;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash};
use halo2wrong::curves::bn256::{Fr as BnScalar, G1Affine as BnG1, G2Affine as BnG2};
use halo2wrong::curves::ff::PrimeField;
use halo2wrong::curves::group::prime::PrimeCurveAffine;
use halo2wrong::curves::group::Curve;
use halo2wrong::curves::grumpkin::{Fr as GkScalar, G1Affine as GkG1};
use halo2wrong::halo2::arithmetic::Field;
use halo2wrong::halo2::circuit::Value;

pub use crate::dkg::{
    combine_partial_evaluations, is_dl_equal, keygen, shares, DkgConfig, DkgShareKey, PseudoRandom,
    EVAL_PREFIX,
};
pub use crate::dkg_circuit::DkgCircuit;
pub use crate::error::Error;
pub use crate::poseidon::P128Pow5T3Bn;
#[cfg(feature = "g2chip")]
use crate::utils::point2_to_public;
use crate::utils::point_to_public;
pub use crate::utils::{hash_to_curve_bn, hash_to_curve_grumpkin, mod_n, rns_setup};

const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LIMBS: usize = 4;
const WRAP_LEN: usize = 2;
const POSEIDON_WIDTH: usize = 3;
const POSEIDON_RATE: usize = 2;
const POSEIDON_LEN: usize = 2;
pub const WINDOW_SIZE: usize = 3;

#[derive(Debug, Clone)]
pub struct MemberKey {
    sk: GkScalar,
    pk: GkG1,
}

impl MemberKey {
    pub fn new(sk: GkScalar, pk: GkG1) -> Self {
        MemberKey { sk, pk }
    }

    pub fn random(mut rng: impl RngCore) -> Self {
        let g = GkG1::generator();
        let sk = GkScalar::random(&mut rng);
        let pk = (g * sk).to_affine();

        MemberKey { sk, pk }
    }

    pub fn public_key(&self) -> GkG1 {
        self.pk
    }

    pub fn secret_key(&self) -> GkScalar {
        self.sk
    }

    pub fn decrypt_share(&self, gr: &GkG1, cipher: &BnScalar) -> BnScalar {
        let pkr = (gr * self.sk).to_affine();
        let poseidon = Hash::<_, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init();
        let key = poseidon.clone().hash([pkr.x, pkr.y]);
        let plaintext = cipher - key;

        plaintext
    }

    // find the index of this member in a list of public keys; member_index is array_index + 1
    pub fn index(&self, public_keys: &[GkG1]) -> Option<usize> {
        public_keys
            .iter()
            .position(|pk| pk.eq(&self.pk))
            .map(|i| i + 1)
    }

    // decrypt ciphers from other members (including its own cipher) and aggregate shares
    pub fn dkg_share_key(
        &self,
        dkg_config: &DkgConfig,
        index: usize,
        pps: &[&DkgMemberPublicParams],
    ) -> Result<DkgShareKey, Error> {
        if index < 1 || index > dkg_config.number_of_members() {
            return Err(Error::InvalidIndex { index });
        }

        let k = index - 1;
        let mut sk = BnScalar::zero();
        for i in 0..dkg_config.number_of_members() {
            let s = self.decrypt_share(&pps[i].gr, &pps[i].ciphers[k]);
            sk += s;
        }

        let g = BnG1::generator();
        let vk = (g * sk).to_affine();

        Ok(DkgShareKey::new(index, sk, vk))
    }
}

#[derive(Clone, Debug)]
pub struct DkgMemberPublicParams {
    // each member is indexed between 1...NUMBER_OF_MEMBERS
    pub index: usize,
    pub public_shares: Vec<BnG1>,
    pub ciphers: Vec<BnScalar>,
    pub gr: GkG1,
    pub ga: BnG1,
    pub g2a: BnG2,
}

impl DkgMemberPublicParams {
    pub fn instance(&self, pks: &[GkG1]) -> Vec<Vec<BnScalar>> {
        let (rns_base, _) = rns_setup::<BnG1>(0);
        let rns_base = Rc::new(rns_base);

        let mut public_data = point_to_public(Rc::clone(&rns_base), self.ga, WRAP_LEN);

        for i in 0..pks.len() {
            let gs_public = point_to_public(Rc::clone(&rns_base), self.public_shares[i], WRAP_LEN);
            public_data.extend(gs_public);
        }

        public_data.push(self.gr.x);
        public_data.push(self.gr.y);

        for i in 0..pks.len() {
            public_data.push(pks[i].x);
            public_data.push(pks[i].y);
            public_data.push(self.ciphers[i]);
        }

        #[cfg(feature = "g2chip")]
        let g2a_public = point2_to_public(Rc::clone(&rns_base), self.g2a, WRAP_LEN);
        #[cfg(feature = "g2chip")]
        public_data.extend(g2a_public);

        let instance = vec![public_data];
        instance
    }

    // check if ga and g2a have the same exponent
    pub fn check_public(&self) -> Result<(), Error> {
        is_dl_equal(&self.ga, &self.g2a)
    }
}

#[derive(Clone, Debug)]
pub struct DkgMemberParams {
    pub dkg_config: DkgConfig,
    pub coeffs: Vec<BnScalar>,
    pub shares: Vec<BnScalar>,
    pub r: BnScalar,
    pub public_keys: Vec<GkG1>,
    pub public_params: DkgMemberPublicParams,
}

impl DkgMemberParams {
    pub fn new(
        dkg_config: DkgConfig,
        index: usize,
        public_keys: Vec<GkG1>,
        mut rng: impl RngCore,
    ) -> Result<Self, Error> {
        assert_eq!(public_keys.len(), dkg_config.number_of_members());

        if index < 1 || index > dkg_config.number_of_members() {
            return Err(Error::InvalidIndex { index });
        }

        // generate random coefficients for polynomial
        let coeffs: Vec<_> = (0..dkg_config.threshold())
            .map(|_| BnScalar::random(&mut rng))
            .collect();

        let g = BnG1::generator();
        let g2 = BnG2::generator();

        // compute main public coefficients
        let ga = (g * coeffs[0]).to_affine();
        let g2a = (g2 * coeffs[0]).to_affine();

        // compute secret shares for members
        let shares = shares(dkg_config.number_of_members(), &coeffs);
        let public_shares: Vec<_> = shares.iter().map(|s| (g * s).to_affine()).collect();

        // draw arandomness for encryption
        let r = BnScalar::random(&mut rng);
        let gg = GkG1::generator();
        let rs = GkScalar::from_repr(r.to_repr())
            .expect("unable to convert Bn256 scalar to Grumpkin scalar");
        let gr = (gg * rs).to_affine();

        // encrypt shares
        let poseidon = Hash::<_, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init();
        let mut ciphers = vec![];
        for i in 0..dkg_config.number_of_members() {
            let pkr = (public_keys[i] * rs).to_affine();
            let key = poseidon.clone().hash([pkr.x, pkr.y]);
            let cipher = key + shares[i];
            ciphers.push(cipher);
        }

        let public_params = DkgMemberPublicParams {
            index,
            public_shares,
            ciphers,
            gr,
            ga,
            g2a,
        };

        Ok(DkgMemberParams {
            dkg_config,
            coeffs,
            shares,
            r,
            public_keys,
            public_params,
        })
    }

    pub fn circuit(&self, mut rng: impl RngCore) -> DkgCircuit {
        let coeffs: Vec<_> = self.coeffs.iter().map(|a| Value::known(*a)).collect();
        let public_keys: Vec<_> = self
            .public_keys
            .iter()
            .map(|pk| Value::known(*pk))
            .collect();

        let grumpkin_aux_generator = Value::known(GkG1::random(&mut rng));
        let circuit = DkgCircuit::new(
            self.dkg_config,
            coeffs,
            Value::known(self.r),
            public_keys,
            grumpkin_aux_generator,
        );

        circuit
    }

    pub fn instance(&self) -> Vec<Vec<BnScalar>> {
        self.public_params.instance(&self.public_keys)
    }

    pub fn member_public_params(&self) -> &DkgMemberPublicParams {
        &self.public_params
    }
}

#[derive(Clone, Debug)]
pub struct DkgGlobalPubParams {
    pub ga: BnG1,
    pub g2a: BnG2,
    pub verify_keys: Vec<BnG1>,
}

impl DkgGlobalPubParams {
    // check if ga and g2a have the same exponent
    pub fn check_public(&self) -> Result<(), Error> {
        is_dl_equal(&self.ga, &self.g2a)
    }
}

pub fn dkg_global_public_params(pps: &[&DkgMemberPublicParams]) -> DkgGlobalPubParams {
    // combine ga and g2a to get global public keys
    let ga = pps
        .iter()
        .skip(1)
        .fold(pps[0].ga, |acc, pp| (acc + pp.ga).to_affine());
    let g2a = pps
        .iter()
        .skip(1)
        .fold(pps[0].g2a, |acc, pp| (acc + pp.g2a).to_affine());

    // compute vk_1, ... vk_n
    let mut vks = vec![];
    let number_of_members = pps[0].public_shares.len();
    for i in 0..number_of_members {
        let mut vk = pps[0].public_shares[i].to_curve();
        for pp in pps.iter().skip(1) {
            vk = vk + pp.public_shares[i];
        }
        vks.push(vk.to_affine());
    }

    DkgGlobalPubParams {
        ga,
        g2a,
        verify_keys: vks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::combine_partial_evaluations;
    use crate::utils::{load_or_create_params, load_or_create_pk, load_or_create_vk};
    use ark_std::{end_timer, start_timer};
    use halo2_ecc::halo2::SerdeFormat;
    use halo2wrong::curves::bn256::Bn256;
    use halo2wrong::halo2::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
    use halo2wrong::halo2::poly::commitment::ParamsProver;
    use halo2wrong::halo2::poly::kzg::commitment::{
        KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG,
    };
    use halo2wrong::halo2::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
    use halo2wrong::halo2::poly::kzg::strategy::SingleStrategy;
    use halo2wrong::halo2::transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    };
    use halo2wrong::utils::{mock_prover_verify, DimensionMeasurement};
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};

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

    fn mock_dkg_circuit(threshold: usize, number_of_members: usize) {
        //let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;

        let dkg_config = DkgConfig::new(threshold, number_of_members).unwrap();
        let (pks, _) = mock_members(&dkg_config, &mut rng);
        // simulate member 1
        let dkg_params = DkgMemberParams::new(dkg_config, 1, pks, &mut rng).unwrap();
        let circuit = dkg_params.circuit(&mut rng);
        let instance = dkg_params.instance();
        println!("total instance {:?}", instance[0].len());

        mock_prover_verify(&circuit, instance);
        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!("dimention: {:?}", dimension);
    }

    #[test]
    fn test_dkg_circuit() {
        #[cfg(not(feature = "g2chip"))]
        {
            // mock_dkg_circuit(5, 9);
            //   mock_dkg_circuit(11, 21);
            //    mock_dkg_circuit(22, 43);
            //    mock_dkg_circuit(45, 88);
            mock_dkg_circuit(89, 176);
        }

        #[cfg(feature = "g2chip")]
        {
            mock_dkg_circuit(3, 5);
            //  mock_dkg_circuit(9, 16);
            //   mock_dkg_circuit(20, 38);
            //   mock_dkg_circuit(42, 83);
            //   mock_dkg_circuit(86, 171);
        }
    }

    #[test]
    #[ignore]
    fn test_pk_vk() {
        // let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;

        let (threshold, number_of_members, degree): (usize, usize, usize) = (3, 5, 18);

        let dkg_config = DkgConfig::new(threshold, number_of_members).unwrap();
        let (pks, _) = mock_members(&dkg_config, &mut rng);
        // simulate member 1
        let dkg_params = DkgMemberParams::new(dkg_config, 1, pks, &mut rng).unwrap();
        let circuit1 = dkg_params.circuit(&mut rng);
        let instance1 = dkg_params.instance();
        mock_prover_verify(&circuit1, instance1);

        let circuit2 = DkgCircuit::dummy(dkg_config);

        let setup_message = format!("dkg setup with degree = {}", degree);
        let start1 = start_timer!(|| setup_message);
        let general_params = ParamsKZG::<Bn256>::setup(degree as u32, &mut rng);
        let _verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
        end_timer!(start1);

        let vk1 = keygen_vk(&general_params, &circuit1).expect("keygen_vk should not fail");
        let vk2 = keygen_vk(&general_params, &circuit2).expect("keygen_vk should not fail");

        assert_eq!(
            vk1.to_bytes(SerdeFormat::RawBytes),
            vk2.to_bytes(SerdeFormat::RawBytes)
        );

        let pk1 = keygen_pk(&general_params, vk1, &circuit1).expect("keygen_pk should not fail");
        let pk2 = keygen_pk(&general_params, vk2, &circuit2).expect("keygen_pk should not fail");

        assert_eq!(
            pk1.to_bytes(SerdeFormat::RawBytes),
            pk2.to_bytes(SerdeFormat::RawBytes)
        );
    }

    fn dkg_proof(threshold: usize, number_of_members: usize, degree: usize) {
        // let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;

        let dkg_config = DkgConfig::new(threshold, number_of_members).unwrap();
        let (mpks, _) = mock_members(&dkg_config, &mut rng);
        let dkg_params = DkgMemberParams::new(dkg_config, 1, mpks, &mut rng).unwrap();
        let circuit = dkg_params.circuit(&mut rng);
        let instance = dkg_params.instance();
        let instance_ref = instance.iter().map(|i| i.as_slice()).collect::<Vec<_>>();

        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!("dimention: {:?}", dimension);

        let start1 = start_timer!(|| format!("kzg setup with degree {}", degree));
        let general_params = ParamsKZG::<Bn256>::setup(degree as u32, &mut rng);
        let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
        end_timer!(start1);

        // Initialize the proving key
        let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");

        {
            let vk_bytes = vk.to_bytes(SerdeFormat::RawBytes);
            println!("size of verification key (raw bytes) {}", vk_bytes.len());
        }

        let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");

        {
            let pk_bytes = pk.to_bytes(SerdeFormat::RawBytes);
            println!("size of proving key (raw bytes) {}", pk_bytes.len());
        }

        // Create a proof
        let mut transcript = Blake2bWrite::<_, BnG1, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let proof_message = format!("dkg proof with degree = {}", degree);
        let start2 = start_timer!(|| proof_message);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<BnG1>,
            _,
            Blake2bWrite<Vec<u8>, BnG1, Challenge255<BnG1>>,
            DkgCircuit,
        >(
            &general_params,
            &pk,
            &[circuit],
            &[instance_ref.as_slice()],
            rng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        end_timer!(start2);

        println!("proof size = {:?}", proof.len());

        let start3 = start_timer!(|| format!("verify snark proof for dkg"));
        let mut verifier_transcript = Blake2bRead::<_, BnG1, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleStrategy::new(&general_params);

        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<BnG1>,
            Blake2bRead<&[u8], BnG1, Challenge255<BnG1>>,
            SingleStrategy<'_, Bn256>,
        >(
            &verifier_params,
            pk.get_vk(),
            strategy,
            &[instance_ref.as_slice()],
            &mut verifier_transcript,
        )
        .expect("failed to verify dkg circuit");
        end_timer!(start3);
    }

    #[test]
    #[ignore]
    fn test_dkg_proof() {
        #[cfg(not(feature = "g2chip"))]
        {
            dkg_proof(5, 9, 18);
            // dkg_proof(11, 21, 19);
            //  dkg_proof(22, 43, 20);
            //  dkg_proof(45, 88, 21);
            //  dkg_proof(89, 176, 22);
        }

        #[cfg(feature = "g2chip")]
        {
            dkg_proof(3, 5, 18);
            //  dkg_proof(9, 16, 19);
            //  dkg_proof(20, 38, 20);
            //  dkg_proof(42, 83, 21);
            //  dkg_proof(86, 171, 22);
        }
    }

    #[test]
    #[ignore]
    fn test_dkg_proof_kzg_params() {
        // let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;

        let (threshold, number_of_members, degree): (usize, usize, usize) = (3, 5, 18);

        let dkg_config = DkgConfig::new(threshold, number_of_members).unwrap();
        let (mpks, _) = mock_members(&dkg_config, &mut rng);
        let dkg_params = DkgMemberParams::new(dkg_config, 1, mpks, &mut rng).unwrap();
        let circuit = dkg_params.circuit(&mut rng);
        let instance = dkg_params.instance();
        let instance_ref = instance.iter().map(|i| i.as_slice()).collect::<Vec<_>>();

        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!("dimention: {:?}", dimension);

        let start1 = start_timer!(|| format!("kzg load or setup with degree {}", degree));
        let params_dir = "./kzg_params";
        let general_params = load_or_create_params(params_dir, degree).unwrap();
        let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
        end_timer!(start1);

        let pk = load_or_create_pk(dkg_config, params_dir, &general_params, degree).unwrap();

        // Create a proof
        let mut transcript = Blake2bWrite::<_, BnG1, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let proof_message = format!("dkg proof with degree = {}", degree);
        let start2 = start_timer!(|| proof_message);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<BnG1>,
            _,
            Blake2bWrite<Vec<u8>, BnG1, Challenge255<BnG1>>,
            DkgCircuit,
        >(
            &general_params,
            &pk,
            &[circuit],
            &[instance_ref.as_slice()],
            rng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        end_timer!(start2);

        println!("proof size = {:?}", proof.len());

        let start3 = start_timer!(|| format!("verify snark proof for dkg"));
        let mut verifier_transcript = Blake2bRead::<_, BnG1, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleStrategy::new(&general_params);
        let vk = load_or_create_vk(dkg_config, params_dir, &general_params, degree).unwrap();

        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<BnG1>,
            Blake2bRead<&[u8], BnG1, Challenge255<BnG1>>,
            SingleStrategy<'_, Bn256>,
        >(
            &verifier_params,
            &vk,
            strategy,
            &[instance_ref.as_slice()],
            &mut verifier_transcript,
        )
        .expect("failed to verify dkg circuit");
        end_timer!(start3);
    }

    fn mock_dvrf(threshold: usize, number_of_members: usize) {
        //let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;

        let dkg_config = DkgConfig::new(threshold, number_of_members).unwrap();
        let (pks, members) = mock_members(&dkg_config, &mut rng);
        let dkgs: Vec<_> = (0..number_of_members)
            .map(|i| DkgMemberParams::new(dkg_config, i + 1, pks.clone(), &mut rng).unwrap())
            .collect();

        let dkgs_pub: Vec<_> = dkgs.iter().map(|dkg| dkg.member_public_params()).collect();

        // simulation skips the snark proof and verify

        #[cfg(not(feature = "g2chip"))]
        {
            // check g1a and g2a have the same exponent
            for &dkg in dkgs_pub.iter() {
                dkg.check_public().unwrap()
            }
        }

        // compute public parameters
        let pp = dkg_global_public_params(&dkgs_pub);

        // each member decrypt to obtain their own shares
        let mut shares = vec![];
        for i in 0..number_of_members {
            assert_eq!(members[i].pk, pks[i]);
            let share = members[i]
                .dkg_share_key(&dkg_config, i + 1, &dkgs_pub)
                .unwrap();
            share.verify(&dkg_config, &pp.verify_keys).unwrap();

            shares.push(share);
        }

        // each member performs partial evaluation
        let input = b"first random";
        let mut sigmas = vec![];
        for i in 0..number_of_members {
            let sigma = shares[i].evaluate(input, &mut rng);
            sigma
                .verify(&dkg_config, input, &pp.verify_keys[i])
                .unwrap();
            sigmas.push(sigma);
        }

        // combine partial evaluations to obtain final random
        let v = combine_partial_evaluations(&dkg_config, &sigmas[0..threshold]).unwrap();
        v.verify(input, &pp.g2a).unwrap();
    }

    #[test]
    fn test_dvrf_functions() {
        mock_dvrf(3, 5);
        mock_dvrf(9, 16);
        mock_dvrf(20, 38);
        mock_dvrf(42, 83);
        mock_dvrf(86, 171);
    }
}
