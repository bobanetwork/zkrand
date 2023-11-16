mod dkg;
mod dkg_circuit;
mod ecc_chip;
mod error;
mod grumpkin_chip;
mod hash_to_curve;
mod poseidon;
mod utils;

pub use utils::{load_or_create_params, load_or_create_pk, load_or_create_vk};

use rand_core::RngCore;
use std::rc::Rc;

pub use halo2_ecc::integer::NUMBER_OF_LOOKUP_LIMBS;
use halo2_ecc::Point;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash};
use halo2wrong::curves::bn256::{Fr as BnScalar, G1Affine as BnG1, G2Affine as BnG2};
use halo2wrong::curves::ff::PrimeField;
use halo2wrong::curves::group::prime::PrimeCurveAffine;
use halo2wrong::curves::group::Curve;
use halo2wrong::curves::grumpkin::{Fr as GkScalar, G1Affine as GkG1};
use halo2wrong::halo2::arithmetic::Field;
use halo2wrong::halo2::circuit::Value;

use crate::dkg::is_dl_equal;
pub use crate::dkg::{
    combine_partial_evaluations, keygen, shares, DkgShareKey, PseudoRandom, EVAL_PREFIX,
};
pub use crate::dkg_circuit::DkgCircuit;
#[cfg(feature = "g2chip")]
use crate::ecc_chip::Point2;
pub use crate::error::Error;
pub use crate::poseidon::P128Pow5T3Bn;
pub use crate::utils::{hash_to_curve_bn, hash_to_curve_grumpkin, mod_n, rns_setup};

const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LIMBS: usize = 4;
const POSEIDON_WIDTH: usize = 3;
const POSEIDON_RATE: usize = 2;
const POSEIDON_LEN: usize = 2;
pub const DEFAULT_WINDOW_SIZE: usize = 3;

pub struct MemberKey {
    sk: GkScalar,
    pk: GkG1,
}

impl MemberKey {
    pub fn new(mut rng: impl RngCore) -> Self {
        let g = GkG1::generator();
        let sk = GkScalar::random(&mut rng);
        let pk = (g * sk).to_affine();

        MemberKey { sk, pk }
    }

    pub fn get_public_key(&self) -> GkG1 {
        self.pk
    }

    pub fn decrypt_share(&self, gr: &GkG1, cipher: &BnScalar) -> BnScalar {
        let pkr = (gr * self.sk).to_affine();
        let poseidon = Hash::<_, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init();
        let key = poseidon.clone().hash([pkr.x, pkr.y]);
        let plaintext = cipher - key;

        plaintext
    }

    // find the index of this member in a list of public keys; member_index is array_index + 1
    pub fn get_index(&self, public_keys: &[GkG1]) -> Option<usize> {
        public_keys
            .iter()
            .position(|pk| pk.eq(&self.pk))
            .map(|i| i + 1)
    }

    // decrypt ciphers from other members (including its own cipher) and aggregate shares
    pub fn dkg_share_key<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>(
        &self,
        index: usize,
        pps: &[&DkgMemberPublicParams<THRESHOLD, NUMBER_OF_MEMBERS>],
    ) -> Result<DkgShareKey<THRESHOLD, NUMBER_OF_MEMBERS>, Error> {
        if index < 1 || index > NUMBER_OF_MEMBERS {
            return Err(Error::InvalidIndex { index });
        }

        let k = index - 1;
        let mut sk = BnScalar::zero();
        for i in 0..NUMBER_OF_MEMBERS {
            let s = self.decrypt_share(&pps[i].gr, &pps[i].ciphers[k]);
            sk += s;
        }

        let g = BnG1::generator();
        let vk = (g * sk).to_affine();

        Ok(DkgShareKey::new(index, sk, vk))
    }
}

#[derive(Clone, Debug)]
pub struct DkgMemberPublicParams<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize> {
    // each member is indexed between 1..NUMBER_OF_MEMBERS
    index: usize,
    public_shares: [BnG1; NUMBER_OF_MEMBERS],
    ciphers: [BnScalar; NUMBER_OF_MEMBERS],
    gr: GkG1,
    ga: BnG1,
    g2a: BnG2,
}

impl<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>
    DkgMemberPublicParams<THRESHOLD, NUMBER_OF_MEMBERS>
{
    pub fn instance(&self, pks: &[GkG1]) -> Vec<Vec<BnScalar>> {
        assert_eq!(pks.len(), NUMBER_OF_MEMBERS);

        let (rns_base, _) = rns_setup::<BnG1>(0);
        let rns_base = Rc::new(rns_base);

        let ga_point = Point::new(Rc::clone(&rns_base), self.ga);
        let mut public_data = ga_point.public();

        for i in 0..NUMBER_OF_MEMBERS {
            let gs_point = Point::new(Rc::clone(&rns_base), self.public_shares[i]);
            public_data.extend(gs_point.public());
        }

        public_data.push(self.gr.x);
        public_data.push(self.gr.y);

        for i in 0..NUMBER_OF_MEMBERS {
            public_data.push(pks[i].x);
            public_data.push(pks[i].y);
            public_data.push(self.ciphers[i]);
        }

        #[cfg(feature = "g2chip")]
        let g2a_point = Point2::new(Rc::clone(&rns_base), self.g2a);
        #[cfg(feature = "g2chip")]
        public_data.extend(g2a_point.public());

        let instance = vec![public_data];
        instance
    }

    // check if ga and g2a have the same exponent
    pub fn check_public(&self) -> Result<(), Error> {
        is_dl_equal(&self.ga, &self.g2a)
    }
}

#[derive(Clone, Debug)]
pub struct DkgMemberParams<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize> {
    coeffs: [BnScalar; THRESHOLD],
    shares: [BnScalar; NUMBER_OF_MEMBERS],
    r: BnScalar,
    public_keys: [GkG1; NUMBER_OF_MEMBERS],
    public_params: DkgMemberPublicParams<THRESHOLD, NUMBER_OF_MEMBERS>,
}

impl<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>
    DkgMemberParams<THRESHOLD, NUMBER_OF_MEMBERS>
{
    pub fn new(index: usize, public_keys: &[GkG1], mut rng: impl RngCore) -> Result<Self, Error> {
        assert_eq!(public_keys.len(), NUMBER_OF_MEMBERS);

        if index < 1 || index > NUMBER_OF_MEMBERS {
            return Err(Error::InvalidIndex { index });
        }

        // generate random coefficients for polynomial
        let coeffs: Vec<_> = (0..THRESHOLD).map(|_| BnScalar::random(&mut rng)).collect();

        let g = BnG1::generator();
        let g2 = BnG2::generator();

        // compute main public coefficients
        let ga = (g * coeffs[0]).to_affine();
        let g2a = (g2 * coeffs[0]).to_affine();

        // compute secret shares for members
        let shares = shares::<THRESHOLD, NUMBER_OF_MEMBERS>(&coeffs);
        let public_shares: Vec<_> = shares.iter().map(|s| (g * s).to_affine()).collect();

        // draw arandomness for encryption
        let r = BnScalar::random(&mut rng);
        let gg = GkG1::generator();
        let rs = GkScalar::from_repr(r.to_repr())
            .expect("unable to convert Bn256 scalar to Grumpkin scalar");
        let ggr = (gg * rs).to_affine();

        // encrypt shares
        let poseidon = Hash::<_, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init();
        let mut ciphers = vec![];
        for i in 0..NUMBER_OF_MEMBERS {
            let pkr = (public_keys[i] * rs).to_affine();
            let key = poseidon.clone().hash([pkr.x, pkr.y]);
            let cipher = key + shares[i];
            ciphers.push(cipher);
        }

        let public_params = DkgMemberPublicParams {
            index,
            public_shares: public_shares
                .try_into()
                .expect("unable to convert public share vector"),
            ciphers: ciphers.try_into().expect("unable to convert cipher vector"),
            gr: ggr,
            ga,
            g2a,
        };

        Ok(DkgMemberParams {
            coeffs: coeffs
                .try_into()
                .expect("unable to convert coefficient vector"),
            shares,
            r,
            public_keys: public_keys
                .try_into()
                .expect("unable to convert public key vector"),
            public_params,
        })
    }

    pub fn circuit(&self, mut rng: impl RngCore) -> DkgCircuit<THRESHOLD, NUMBER_OF_MEMBERS> {
        let coeffs: Vec<_> = self.coeffs.iter().map(|a| Value::known(*a)).collect();
        let public_keys: Vec<_> = self
            .public_keys
            .iter()
            .map(|pk| Value::known(*pk))
            .collect();

        let grumpkin_aux_generator = Value::known(GkG1::random(&mut rng));
        let circuit = DkgCircuit::<THRESHOLD, NUMBER_OF_MEMBERS>::new(
            coeffs,
            Value::known(self.r),
            public_keys,
            DEFAULT_WINDOW_SIZE,
            grumpkin_aux_generator,
        );

        circuit
    }

    pub fn instance(&self) -> Vec<Vec<BnScalar>> {
        self.public_params.instance(&self.public_keys)
    }

    pub fn member_public_params(&self) -> &DkgMemberPublicParams<THRESHOLD, NUMBER_OF_MEMBERS> {
        &self.public_params
    }
}

#[derive(Clone, Debug)]
pub struct DkgGlobalPubParams<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize> {
    ga: BnG1,
    g2a: BnG2,
    verify_keys: [BnG1; NUMBER_OF_MEMBERS],
}

impl<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>
    DkgGlobalPubParams<THRESHOLD, NUMBER_OF_MEMBERS>
{
    // check if ga and g2a have the same exponent
    pub fn check_public(&self) -> Result<(), Error> {
        is_dl_equal(&self.ga, &self.g2a)
    }
}

pub fn dkg_global_public_params<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>(
    pps: &[&DkgMemberPublicParams<THRESHOLD, NUMBER_OF_MEMBERS>],
) -> DkgGlobalPubParams<THRESHOLD, NUMBER_OF_MEMBERS> {
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
    for i in 0..NUMBER_OF_MEMBERS {
        let mut vk = pps[0].public_shares[i].to_curve();
        for pp in pps.iter().skip(1) {
            vk = vk + pp.public_shares[i];
        }
        vks.push(vk.to_affine());
    }

    DkgGlobalPubParams {
        ga,
        g2a,
        verify_keys: vks
            .try_into()
            .expect("unable to convert vks vector to arrays"),
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

    fn get_members<const NUMBER_OF_MEMBERS: usize>(
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

    fn mock_dkg_circuit<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>() {
        // let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;

        let (pks, _) = get_members::<NUMBER_OF_MEMBERS>(&mut rng);
        // simulate member 1
        let dkg_params =
            DkgMemberParams::<THRESHOLD, NUMBER_OF_MEMBERS>::new(1, &pks, &mut rng).unwrap();
        let circuit = dkg_params.circuit(&mut rng);
        let instance = dkg_params.instance();
        mock_prover_verify(&circuit, instance);
        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!("dimention: {:?}", dimension);
    }

    #[test]
    fn test_dkg_circuit() {
        #[cfg(not(feature = "g2chip"))]
        {
            mock_dkg_circuit::<5, 9>();
            //   mock_dkg_circuit::<11, 21>();
            //    mock_dkg_circuit::<22, 43>();
            //    mock_dkg_circuit::<45, 89>();
            //    mock_dkg_circuit::<90, 178>();
        }

        #[cfg(feature = "g2chip")]
        {
            mock_dkg_circuit::<3, 5>();
            //  mock_dkg_circuit::<9, 16>();
            //   mock_dkg_circuit::<20, 39>();
            //    mock_dkg_circuit::<43, 84>();
            //     mock_dkg_circuit::<87, 173>();
        }
    }

    #[test]
    #[ignore]
    fn test_pk_vk() {
        // let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;

        #[cfg(not(feature = "g2chip"))]
        const THRESHOLD: usize = 5;
        #[cfg(not(feature = "g2chip"))]
        const NUMBER_OF_MEMBERS: usize = 9;

        #[cfg(feature = "g2chip")]
        const THRESHOLD: usize = 3;
        #[cfg(feature = "g2chip")]
        const NUMBER_OF_MEMBERS: usize = 5;

        let degree = 18;

        let (pks, _) = get_members::<NUMBER_OF_MEMBERS>(&mut rng);
        // simulate member 1
        let dkg_params =
            DkgMemberParams::<THRESHOLD, NUMBER_OF_MEMBERS>::new(1, &pks, &mut rng).unwrap();
        let circuit1 = dkg_params.circuit(&mut rng);
        let instance1 = dkg_params.instance();
        mock_prover_verify(&circuit1, instance1);

        let circuit2 = DkgCircuit::<THRESHOLD, NUMBER_OF_MEMBERS>::dummy(DEFAULT_WINDOW_SIZE);

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

    fn dkg_proof<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize, const DEGREE: usize>() {
        // let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;

        let (mpks, _) = get_members::<NUMBER_OF_MEMBERS>(&mut rng);
        let dkg_params =
            DkgMemberParams::<THRESHOLD, NUMBER_OF_MEMBERS>::new(1, &mpks, &mut rng).unwrap();
        let circuit = dkg_params.circuit(&mut rng);
        let instance = dkg_params.instance();
        let instance_ref = instance.iter().map(|i| i.as_slice()).collect::<Vec<_>>();

        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!("dimention: {:?}", dimension);

        let start1 = start_timer!(|| format!("kzg setup with degree {}", DEGREE));
        let general_params = ParamsKZG::<Bn256>::setup(DEGREE as u32, &mut rng);
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
        let proof_message = format!("dkg proof with degree = {}", DEGREE);
        let start2 = start_timer!(|| proof_message);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<BnG1>,
            _,
            Blake2bWrite<Vec<u8>, BnG1, Challenge255<BnG1>>,
            DkgCircuit<THRESHOLD, NUMBER_OF_MEMBERS>,
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
            dkg_proof::<5, 9, 18>();
            // dkg_proof::<11, 21, 19>();
            //  dkg_proof::<22, 43, 20>();
            //  dkg_proof::<45, 89, 21>();
            //  dkg_proof::<90, 178, 22>();
        }

        #[cfg(feature = "g2chip")]
        {
            dkg_proof::<3, 5, 18>();
            //  dkg_proof::<9, 16, 19>();
            //  dkg_proof::<20, 39, 20>();
            //  dkg_proof::<43, 84, 21>();
            //  dkg_proof::<88, 174, 22>();
        }
    }

    #[test]
    #[ignore]
    fn test_dkg_proof_kzg_params() {
        // let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut rng = OsRng;
        const THRESHOLD: usize = 3;
        const NUMBER_OF_MEMBERS: usize = 5;
        const DEGREE: usize = 18;

        let (mpks, _) = get_members::<NUMBER_OF_MEMBERS>(&mut rng);
        let dkg_params =
            DkgMemberParams::<THRESHOLD, NUMBER_OF_MEMBERS>::new(1, &mpks, &mut rng).unwrap();
        let circuit = dkg_params.circuit(&mut rng);
        let instance = dkg_params.instance();
        let instance_ref = instance.iter().map(|i| i.as_slice()).collect::<Vec<_>>();

        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!("dimention: {:?}", dimension);

        let start1 = start_timer!(|| format!("kzg load or setup with degree {}", DEGREE));
        let params_dir = "./kzg_params";
        let general_params = load_or_create_params(params_dir, DEGREE).unwrap();
        let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
        end_timer!(start1);

        let pk =
            load_or_create_pk::<THRESHOLD, NUMBER_OF_MEMBERS>(params_dir, &general_params, DEGREE)
                .unwrap();

        // Create a proof
        let mut transcript = Blake2bWrite::<_, BnG1, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let proof_message = format!("dkg proof with degree = {}", DEGREE);
        let start2 = start_timer!(|| proof_message);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<BnG1>,
            _,
            Blake2bWrite<Vec<u8>, BnG1, Challenge255<BnG1>>,
            DkgCircuit<THRESHOLD, NUMBER_OF_MEMBERS>,
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
        let vk =
            load_or_create_vk::<THRESHOLD, NUMBER_OF_MEMBERS>(params_dir, &general_params, DEGREE)
                .unwrap();

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

    fn mock_dvrf<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let (pks, members) = get_members::<NUMBER_OF_MEMBERS>(&mut rng);
        let dkgs: Vec<_> = (0..NUMBER_OF_MEMBERS)
            .map(|i| {
                DkgMemberParams::<THRESHOLD, NUMBER_OF_MEMBERS>::new(i + 1, &pks, &mut rng).unwrap()
            })
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
        for i in 0..NUMBER_OF_MEMBERS {
            assert_eq!(members[i].pk, pks[i]);
            let share = members[i].dkg_share_key(i + 1, &dkgs_pub).unwrap();
            share.verify(&pp.verify_keys).unwrap();

            shares.push(share);
        }

        // each member performs partial evaluation
        let input = b"first random";
        let mut sigmas = vec![];
        for i in 0..NUMBER_OF_MEMBERS {
            let sigma = shares[i].evaluate(input, &mut rng);
            sigma.verify(input, &pp.verify_keys[i]).unwrap();
            sigmas.push(sigma);
        }

        // combine partial evaluations to obtain final random
        let v = combine_partial_evaluations(&sigmas[0..THRESHOLD]).unwrap();
        v.verify(input, &pp.g2a).unwrap();
    }

    #[test]
    fn test_dvrf_functions() {
        mock_dvrf::<5, 9>();
        mock_dvrf::<11, 21>();
        mock_dvrf::<22, 43>();
        //  mock_dvrf::<45, 89>();
        //  mock_dvrf::<89, 177>();
    }
}
