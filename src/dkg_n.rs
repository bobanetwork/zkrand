use halo2wrong::curves::{
    bn256::{Fq as BnBase, Fr as BnScalar, G1Affine as BnG1},
    ff::PrimeField,
};
use halo2wrong::halo2::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};

use halo2_ecc::integer::rns::Rns;
use halo2_ecc::maingate::RegionCtx;
use halo2_ecc::{BaseFieldEccChip, EccConfig, Point};
use halo2_gadgets::poseidon::{
    primitives::ConstantLength, Hash as PoseidonHash, Pow5Chip, Pow5Config,
};
use halo2_maingate::{
    MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
};

use crate::poseidon::P128Pow5T3Bn;
use crate::{
    BIT_LEN_LIMB, NUMBER_OF_LIMBS, NUMBER_OF_MEMBERS, POSEIDON_LEN, POSEIDON_RATE, POSEIDON_WIDTH,
    THRESHOLD,
};

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
    ) -> Result<(), Error> {
        let range_chip = RangeChip::<N>::new(self.range_config.clone());
        range_chip.load_table(layouter)?;

        Ok(())
    }
}

#[derive(Default, Clone)]
struct CircuitDkg {
    coeffs: [Value<BnScalar>; THRESHOLD],
    random: Value<BnScalar>,
    public_keys: [Value<BnG1>; NUMBER_OF_MEMBERS],

    aux_generator: BnG1,
    window_size: usize,
}

impl Circuit<BnScalar> for CircuitDkg {
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
    ) -> Result<(), Error> {
        let ecc_chip_config = config.ecc_chip_config();
        let mut ecc_chip =
            BaseFieldEccChip::<BnG1, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);
        let main_gate = MainGate::<BnScalar>::new(config.main_gate_config.clone());

        let shares = layouter.assign_region(
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
                    let mut x = i;
                    let mut s = coeffs[0].clone();
                    for j in 1..THRESHOLD {
                        let y = main_gate.assign_constant(ctx, BnScalar::from(x as u64))?;
                        s = main_gate.mul_add(ctx, &coeffs[j], &y, &s)?;
                        x = x * i;
                    }
                    shares.push(s);
                }

                Ok(shares)
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

        let (g, r, gr) = layouter.assign_region(
            || "region ecc mul g^r",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let g = ecc_chip.assign_constant(ctx, BnG1::generator())?;
                let r = main_gate.assign_value(ctx, self.random)?;

                // gr = g^r
                let gr = ecc_chip.mul(ctx, &g, &r, self.window_size)?;
                // normalise for public inputs
                let gr = ecc_chip.normalize(ctx, &gr)?;

                Ok((g, r, gr))
            },
        )?;

        ecc_chip.expose_public(layouter.namespace(|| "cipher g^r"), gr, 0)?;
        let mut instance_offset: usize = 8;

        for i in 0..NUMBER_OF_MEMBERS {
            let (gs, pkr) = layouter.assign_region(
                || "region ecc mul",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let pk_assigned = ecc_chip.assign_point(ctx, self.public_keys[i])?;

                    // gs = g^s, pkr = pk^r
                    let gs = ecc_chip.mul(ctx, &g, &shares[i], self.window_size)?;
                    let pkr = ecc_chip.mul(ctx, &pk_assigned, &r, self.window_size)?;

                    // normalise for public inputs
                    let gs = ecc_chip.normalize(ctx, &gs)?;
                    let pkr = ecc_chip.normalize(ctx, &pkr)?;
                    Ok((gs, pkr))
                },
            )?;

            let message = [pkr.x().native().clone(), pkr.y().native().clone()];

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

            ecc_chip.expose_public(layouter.namespace(|| "g^s"), gs, instance_offset)?;
            instance_offset += 8;
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

    use crate::DEGREE;
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

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::rc::Rc;

    use super::*;
    use crate::poseidon::P128Pow5T3Bn;
    use crate::utils::{create_shares, mod_n, setup};

    fn get_circuit() -> (CircuitDkg, Vec<BnScalar>, ChaCha20Rng) {
        let (rns_base, _) = setup::<BnG1>(0);
        let rns_base = Rc::new(rns_base);

        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let g = BnG1::generator();

        // Generate a key pair for encryption
        let mut sks = vec![];
        let mut pks = vec![];

        for _ in 0..NUMBER_OF_MEMBERS {
            let sk = BnScalar::random(&mut rng);
            let pk = (g * sk).to_affine();

            sks.push(sk);
            pks.push(pk);
        }

        // Draw arandomness for encryption
        let random = BnScalar::random(&mut rng);
        let gr = (g * random).to_affine();

        let gr_point = Point::new(Rc::clone(&rns_base), gr);
        let mut public_data = gr_point.public();

        let mut coeffs = vec![];
        for _ in 0..THRESHOLD {
            let a = BnScalar::random(&mut rng);
            coeffs.push(a);
        }

        let shares = create_shares(&coeffs);
        let poseidon = Hash::<_, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init();

        let mut gss = vec![];
        for i in 0..NUMBER_OF_MEMBERS {
            let gs = (g * shares[i]).to_affine();
            gss.push(gs);

            // Encrypt
            let pkr = (pks[i] * random).to_affine();
            let message = [mod_n::<BnG1>(pkr.x), mod_n::<BnG1>(pkr.y)];
            let key = poseidon.clone().hash(message);
            let cipher = key + shares[i];

            let gs_point = Point::new(Rc::clone(&rns_base), gs);
            public_data.extend(gs_point.public());

            public_data.push(cipher);
        }

        let coeffs: Vec<_> = coeffs.iter().map(|a| Value::known(*a)).collect();
        let public_keys: Vec<_> = pks.iter().map(|pk| Value::known(*pk)).collect();

        let aux_generator = BnG1::random(&mut rng);
        let circuit = CircuitDkg {
            coeffs: coeffs.try_into().unwrap(),
            random: Value::known(random),
            public_keys: public_keys.try_into().unwrap(),
            aux_generator,
            window_size: 4,
        };

        (circuit, public_data, rng)
    }

    #[test]
    fn test_dkg_n_circuit() {
        let (circuit, public_data, _) = get_circuit();

        let instance = vec![public_data];
        mock_prover_verify(&circuit, instance);

        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!("dimention: {:?}", dimension);
    }

    #[test]
    fn test_dkg_n_proof() {
        let (circuit, public_data, mut rng) = get_circuit();
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

        let vk_bytes = vk.to_bytes(SerdeFormat::RawBytes);
        println!("size of verification key (raw bytes) {}", vk_bytes.len());

        let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");

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
            CircuitDkg,
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
}
