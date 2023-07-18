use halo2wrong::curves::{
    bn256::{Fq as BnBase, Fr as BnScalar, G1Affine as BnG1},
    ff::PrimeField,
    grumpkin::G1Affine as GkG1,
};
use halo2wrong::halo2::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error as PlonkError},
};

use halo2_ecc::integer::rns::Rns;
use halo2_ecc::maingate::RegionCtx;
use halo2_ecc::{BaseFieldEccChip, EccConfig};
use halo2_gadgets::poseidon::{
    primitives::ConstantLength, Hash as PoseidonHash, Pow5Chip, Pow5Config,
};
use halo2_maingate::{
    MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
};

use crate::grumpkin_chip::GrumpkinChip;
use crate::poseidon::P128Pow5T3Bn;
use crate::{BIT_LEN_LIMB, NUMBER_OF_LIMBS, POSEIDON_LEN, POSEIDON_RATE, POSEIDON_WIDTH};

#[derive(Clone, Debug)]
pub struct CircuitDkgConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
    poseidon_config: Pow5Config<BnScalar, POSEIDON_WIDTH, POSEIDON_RATE>,
}

impl CircuitDkgConfig {
    pub fn new(meta: &mut ConstraintSystem<BnScalar>) -> Self {
        let rns = Rns::<BnBase, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct();
        let main_gate_config = MainGate::<BnScalar>::configure(meta);
        let overflow_bit_lens = rns.overflow_lengths();
        let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

        let range_config = RangeChip::<BnScalar>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        // poseidon configure
        let state = (0..POSEIDON_WIDTH)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..POSEIDON_WIDTH)
            .map(|_| meta.fixed_column())
            .collect::<Vec<_>>();
        let rc_b = (0..POSEIDON_WIDTH)
            .map(|_| meta.fixed_column())
            .collect::<Vec<_>>();
        meta.enable_constant(rc_b[0]);

        let poseidon_config = Pow5Chip::configure::<P128Pow5T3Bn>(
            meta,
            state.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        CircuitDkgConfig {
            main_gate_config,
            range_config,
            poseidon_config,
        }
    }

    pub fn ecc_chip_config(&self) -> EccConfig {
        EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }

    pub fn config_range<N: PrimeField>(
        &self,
        layouter: &mut impl Layouter<N>,
    ) -> Result<(), PlonkError> {
        let range_chip = RangeChip::<N>::new(self.range_config.clone());
        range_chip.load_table(layouter)?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct CircuitDkg<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize> {
    coeffs: [Value<BnScalar>; THRESHOLD],
    random: Value<BnScalar>,
    public_keys: [Value<GkG1>; NUMBER_OF_MEMBERS],
    aux_generator: BnG1,
    window_size: usize,
    grumpkin_aux_generator: GkG1,
}

impl<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>
    CircuitDkg<THRESHOLD, NUMBER_OF_MEMBERS>
{
    pub fn new(
        coeffs: Vec<Value<BnScalar>>,
        random: Value<BnScalar>,
        public_keys: Vec<Value<GkG1>>,
        aux_generator: BnG1,
        window_size: usize,
        grumpkin_aux_generator: GkG1,
    ) -> Self {
        assert_eq!(coeffs.len(), THRESHOLD);
        assert_eq!(public_keys.len(), NUMBER_OF_MEMBERS);

        CircuitDkg {
            coeffs: coeffs
                .try_into()
                .expect("unable to convert coefficient vector"),
            random,
            public_keys: public_keys
                .try_into()
                .expect("unable to convert public key vector"),
            aux_generator,
            window_size,
            grumpkin_aux_generator,
        }
    }
}

impl<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize> Circuit<BnScalar>
    for CircuitDkg<THRESHOLD, NUMBER_OF_MEMBERS>
{
    type Config = CircuitDkgConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<BnScalar>) -> Self::Config {
        CircuitDkgConfig::new(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<BnScalar>,
    ) -> Result<(), PlonkError> {
        let ecc_chip_config = config.ecc_chip_config();
        let mut ecc_chip =
            BaseFieldEccChip::<BnG1, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);
        let main_gate = MainGate::<BnScalar>::new(config.main_gate_config.clone());
        let mut grumpkin_chip = GrumpkinChip::new(config.main_gate_config.clone());

        let (shares, a) = layouter.assign_region(
            || "region compute shares from coefficients",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let mut coeffs = vec![];
                for a in self.coeffs.iter() {
                    let a_assigned = main_gate.assign_value(ctx, *a)?;
                    coeffs.push(a_assigned);
                }

                let mut shares = vec![];

                // compute s0
                let mut s0 = coeffs[0].clone();
                for j in 1..THRESHOLD {
                    s0 = main_gate.add(ctx, &s0, &coeffs[j])?;
                }
                shares.push(s0);

                // compute s1,..., s_n-1
                for i in 2..=NUMBER_OF_MEMBERS {
                    let ii = BnScalar::from(i as u64);
                    let mut x = ii;
                    let mut s = coeffs[0].clone();
                    for j in 1..THRESHOLD {
                        let y = main_gate.assign_constant(ctx, x)?;
                        s = main_gate.mul_add(ctx, &coeffs[j], &y, &s)?;
                        x = x * ii;
                    }
                    shares.push(s);
                }

                Ok((shares, coeffs[0].clone()))
            },
        )?;

        layouter.assign_region(
            || "assign aux values",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                ecc_chip.assign_aux_generator(ctx, Value::known(self.aux_generator))?;
                ecc_chip.assign_aux(ctx, self.window_size, 1)?;
                //      ecc_chip.get_mul_aux(self.window_size, 1)?;
                Ok(())
            },
        )?;

        layouter.assign_region(
            || "assign aux values for grumpkin chip",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                grumpkin_chip
                    .assign_aux_generator(ctx, Value::known(self.grumpkin_aux_generator))?;
                grumpkin_chip.assign_aux_sub(ctx)?;
                Ok(())
            },
        )?;

        let (g, ga) = layouter.assign_region(
            || "region ecc mul g^a",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let g = ecc_chip.assign_constant(ctx, BnG1::generator())?;

                // ga = g^a
                let ga = ecc_chip.mul(ctx, &g, &a, self.window_size)?;
                // normalise for public inputs
                let ga = ecc_chip.normalize(ctx, &ga)?;

                Ok((g, ga))
            },
        )?;

        ecc_chip.expose_public(layouter.namespace(|| "cipher g^a"), ga, 0)?;
        let mut instance_offset: usize = 8;

        let (bits, gr) = layouter.assign_region(
            || "region grumpkin ecc mul g^r",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let g = grumpkin_chip.assign_constant(ctx, GkG1::generator())?;

                // we don't care about the value of r; if r==0, add will fail
                let bits = grumpkin_chip.to_bits_unsafe(ctx, &self.random)?;
                // gr = g^r
                let gr = grumpkin_chip.mul_bits(ctx, &g, &bits)?;

                Ok((bits, gr))
            },
        )?;

        grumpkin_chip.expose_public(layouter.namespace(|| "cipher g^r"), gr, instance_offset)?;
        instance_offset += 2;

        for i in 0..NUMBER_OF_MEMBERS {
            let gs = layouter.assign_region(
                || "region ecc mul g^s",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    // gs = g^s
                    let gs = ecc_chip.mul(ctx, &g, &shares[i], self.window_size)?;
                    // normalise for public inputs
                    let gs = ecc_chip.normalize(ctx, &gs)?;
                    Ok(gs)
                },
            )?;

            ecc_chip.expose_public(layouter.namespace(|| "g^s"), gs, instance_offset)?;
            instance_offset += 8;
        }

        for i in 0..NUMBER_OF_MEMBERS {
            let (pkr, pk) = layouter.assign_region(
                || "region grumpkin ecc mul encryption",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let pk = grumpkin_chip.assign_point(ctx, self.public_keys[i])?;
                    // pkr = pk^r
                    let pkr = grumpkin_chip.mul_bits(ctx, &pk, &bits)?;

                    Ok((pkr, pk))
                },
            )?;

            grumpkin_chip.expose_public(layouter.namespace(|| "pk"), pk, instance_offset)?;
            instance_offset += 2;

            let message = [pkr.x, pkr.y];

            let poseidon_chip = Pow5Chip::construct(config.poseidon_config.clone());
            let hasher = PoseidonHash::<
                _,
                _,
                P128Pow5T3Bn,
                ConstantLength<POSEIDON_LEN>,
                POSEIDON_WIDTH,
                POSEIDON_RATE,
            >::init(poseidon_chip, layouter.namespace(|| "poseidon init"))?;
            let key = hasher.hash(layouter.namespace(|| "hash"), message)?;

            let cipher = layouter.assign_region(
                || "region add",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    main_gate.add(ctx, &shares[i], &key)
                },
            )?;

            main_gate.expose_public(
                layouter.namespace(|| "cipher main"),
                cipher,
                instance_offset,
            )?;
            instance_offset += 1;
        }

        // todo: move?
        config.config_range(&mut layouter)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash};
    use halo2wrong::curves::group::Curve;
    use halo2wrong::utils::{mock_prover_verify, DimensionMeasurement};

    use ark_std::{end_timer, start_timer};
    use halo2_ecc::halo2::SerdeFormat;
    use halo2wrong::curves::bn256::Bn256;
    use halo2wrong::curves::grumpkin::{Fr as GkScalar, G1Affine as GkG1};
    use halo2wrong::halo2::arithmetic::Field;
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

    use crate::dkg::get_shares;
    use halo2_ecc::Point;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};
    use std::rc::Rc;

    use super::*;
    use crate::poseidon::P128Pow5T3Bn;
    use crate::utils::{mod_n, setup};

    fn get_circuit<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>(
        mut rng: impl RngCore,
    ) -> (CircuitDkg<THRESHOLD, NUMBER_OF_MEMBERS>, Vec<BnScalar>) {
        let (rns_base, _) = setup::<BnG1>(0);
        let rns_base = Rc::new(rns_base);

        let g = BnG1::generator();
        let gg = GkG1::generator();

        // Generate a key pair for encryption
        let mut sks = vec![];
        let mut pks = vec![];
        for _ in 0..NUMBER_OF_MEMBERS {
            let sk = GkScalar::random(&mut rng);
            let pk = (gg * sk).to_affine();

            sks.push(sk);
            pks.push(pk);
        }

        let mut coeffs = vec![];
        for _ in 0..THRESHOLD {
            let a = BnScalar::random(&mut rng);
            coeffs.push(a);
        }

        let ga = (g * coeffs[0]).to_affine();
        let ga_point = Point::new(Rc::clone(&rns_base), ga);
        let mut public_data = ga_point.public();

        // Draw arandomness for encryption
        let random = BnScalar::random(&mut rng);
        let rs = GkScalar::from_repr(random.to_repr()).unwrap();
        let gr = (gg * rs).to_affine();

        public_data.push(gr.x);
        public_data.push(gr.y);

        let shares = get_shares::<THRESHOLD, NUMBER_OF_MEMBERS>(&coeffs);

        let poseidon = Hash::<_, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init();

        for i in 0..NUMBER_OF_MEMBERS {
            let gs = (g * shares[i]).to_affine();
            let gs_point = Point::new(Rc::clone(&rns_base), gs);
            public_data.extend(gs_point.public());
        }

        for i in 0..NUMBER_OF_MEMBERS {
            // Encrypt
            let pkr = (pks[i] * rs).to_affine();
            let key = poseidon.clone().hash([pkr.x, pkr.y]);
            let cipher = key + shares[i];

            public_data.push(pks[i].x);
            public_data.push(pks[i].y);
            public_data.push(cipher);
        }

        let coeffs: Vec<_> = coeffs.iter().map(|a| Value::known(*a)).collect();
        let public_keys: Vec<_> = pks.iter().map(|pk| Value::known(*pk)).collect();

        let aux_generator = BnG1::random(&mut rng);
        let grumpkin_aux_generator = GkG1::random(&mut rng);
        let circuit = CircuitDkg {
            coeffs: coeffs.try_into().unwrap(),
            random: Value::known(random),
            public_keys: public_keys.try_into().unwrap(),
            aux_generator,
            window_size: 4,
            grumpkin_aux_generator,
        };

        (circuit, public_data)
    }

    fn dkg_n_circuit<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (circuit, public_data) = get_circuit::<THRESHOLD, NUMBER_OF_MEMBERS>(&mut rng);
        let instance = vec![public_data];
        mock_prover_verify(&circuit, instance);

        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!(
            "({}, {}) dimention: {:?}",
            THRESHOLD, NUMBER_OF_MEMBERS, dimension
        );
    }

    #[test]
    fn test_dkg_n_circuit() {
        dkg_n_circuit::<3, 5>();
        dkg_n_circuit::<7, 12>();
        //  dkg_n_circuit::<13, 25>();
        //   dkg_n_circuit::<26, 50>();
        //    dkg_n_circuit::<51, 101>();
    }

    #[test]
    fn test_vk() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (circuit1, public_data1) = get_circuit::<3, 5>(&mut rng);
        let (circuit2, public_data2) = get_circuit::<3, 5>(&mut rng);

        let degree = 19;
        let setup_message = format!("dkg setup with degree = {}", degree);
        let start1 = start_timer!(|| setup_message);
        let general_params = ParamsKZG::<Bn256>::setup(degree as u32, &mut rng);
        let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
        end_timer!(start1);

        let vk1 = keygen_vk(&general_params, &circuit1).expect("keygen_vk should not fail");
        let vk2 = keygen_vk(&general_params, &circuit2).expect("keygen_vk should not fail");

        assert_eq!(
            vk1.to_bytes(SerdeFormat::RawBytes),
            vk2.to_bytes(SerdeFormat::RawBytes)
        )
    }

    fn dkg_n_proof<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize, const DEGREE: usize>() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (circuit, public_data) = get_circuit::<THRESHOLD, NUMBER_OF_MEMBERS>(&mut rng);
        let instance = vec![public_data];
        let instance_ref = instance.iter().map(|i| i.as_slice()).collect::<Vec<_>>();

        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!("dimention: {:?}", dimension);

        let degree = DEGREE;
        let setup_message = format!("dkg setup with degree = {}", degree);
        let start1 = start_timer!(|| setup_message);
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
            ChaCha20Rng,
            Blake2bWrite<Vec<u8>, BnG1, Challenge255<BnG1>>,
            CircuitDkg<THRESHOLD, NUMBER_OF_MEMBERS>,
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
    fn test_dkg_n_proof() {
        dkg_n_proof::<3, 5, 19>();
        //        dkg_n_proof::<7, 12, 20>();
    }
}
