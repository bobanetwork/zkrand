use halo2wrong::curves::ff::PrimeField;
use halo2wrong::halo2::{
    arithmetic::{CurveAffine, Field},
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};

use std::marker::PhantomData;

use halo2_ecc::integer::rns::Rns;
use halo2_ecc::integer::{
    rns::Integer, AssignedInteger, IntegerConfig, IntegerInstructions, Range,
};
use halo2_ecc::maingate::RegionCtx;
use halo2_ecc::{AssignedPoint, BaseFieldEccChip, EccConfig, GeneralEccChip, Point};
use halo2_gadgets::poseidon::primitives::ConstantLength;
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
use halo2_maingate::{
    MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
};

use halo2wrong::curves::bn256::{Bn256, Fq as BnBase, Fr as BnScalar, G1Affine as BnG1};
use halo2wrong::halo2::plonk::Selector;
use halo2wrong::halo2::poly::Rotation;

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
    secret: [Value<BnScalar>; NUMBER_OF_MEMBERS],
    random: Value<BnScalar>,
    public_key: [Value<BnG1>; NUMBER_OF_MEMBERS],

    aux_generator: BnG1,
    window_size: usize,
    //    _marker: PhantomData<N>,
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
            let (s, gs, pkr) = layouter.assign_region(
                || "region ecc mul",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let s = main_gate.assign_value(ctx, self.secret[i])?;
                    let pk_assigned = ecc_chip.assign_point(ctx, self.public_key[i])?;

                    // gs = g^s, pkr = pk^r
                    let gs = ecc_chip.mul(ctx, &g, &s, self.window_size)?;
                    let pkr = ecc_chip.mul(ctx, &pk_assigned, &r, self.window_size)?;

                    // normalise for public inputs
                    let gs = ecc_chip.normalize(ctx, &gs)?;
                    let pkr = ecc_chip.normalize(ctx, &pkr)?;
                    Ok((s, gs, pkr))
                },
            )?;

            //   println!("\ngs in circuit = {:?}", gs);

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
            //  println!("\nkey in circuit = {:?}", key.value());

            let cipher = layouter.assign_region(
                || "region add",
                |mut region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    main_gate.add(ctx, &s, &key)
                },
            )?;

            //  println!("\ncipher in circuit = {:?}", cipher.value());

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
    use halo2_ecc::integer::rns::Rns;
    use halo2_ecc::integer::NUMBER_OF_LOOKUP_LIMBS;
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};
    use halo2wrong::curves::group::Curve;
    use halo2wrong::curves::CurveAffine;
    use halo2wrong::utils::{big_to_fe, fe_to_big, mock_prover_verify, DimensionMeasurement};

    use crate::DEGREE;
    use ark_std::{end_timer, start_timer};
    use halo2_ecc::halo2::SerdeFormat;
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
    use rand_core::{OsRng, SeedableRng};
    use std::rc::Rc;

    use super::*;
    use crate::poseidon::P128Pow5T3Bn;
    use crate::utils::{mod_n, rns, setup};

    #[test]
    fn test_dkg_n_circuit() {
        let (rns_base, _) = setup::<BnG1>(0);
        let rns_base = Rc::new(rns_base);

        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let g = BnG1::generator();

        // Generate a key pair for encryption
        let mut sks = vec![];
        let mut pks = vec![];

        for i in 0..NUMBER_OF_MEMBERS {
            let sk = BnScalar::random(&mut rng);
            let pk = (g * sk).to_affine();

            //   println!("\nsk = {:?}\n", sk);
            //   println!("\npk = {:?}\n", pk);

            sks.push(sk);
            pks.push(pk);
        }

        // Draw arandomness for encryption
        let random = BnScalar::random(&mut rng);
        let gr = (g * random).to_affine();

        let gr_point = Point::new(Rc::clone(&rns_base), gr);
        let mut public_data = gr_point.public();

        let mut secrets = vec![];
        let mut gss = vec![];

        let mut poseidon = Hash::<_, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init();

        for i in 0..NUMBER_OF_MEMBERS {
            //  println!("{} th loop", i);
            let secret = BnScalar::random(&mut rng);
            let gs = (g * secret).to_affine();
            //  println!("\nsecret = {:?}", secret);
            //  println!("\ngs = {:?}", gs);

            secrets.push(Value::known(secret));
            gss.push(gs);

            // Encrypt
            let pkr = (pks[i] * random).to_affine();
            let message = [mod_n::<BnG1>(pkr.x), mod_n::<BnG1>(pkr.y)];
            let key = poseidon.clone().hash(message);
            //   println!("\nrandom = {:?}", random);
            //   println!("\ngr = {:?}", gr);
            //   println!("\npkr = {:?}", pkr);
            //  println!("\nkey = {:?}", key);
            //  println!("\nsecret = {:?}", secret);
            let cipher = key + secret;
            //  println!("\ncipher = {:?}", cipher);

            let gs_point = Point::new(Rc::clone(&rns_base), gs);
            public_data.extend(gs_point.public());

            public_data.push(cipher);
        }

        let public_key: Vec<_> = pks.iter().map(|pk| Value::known(*pk)).collect();

        let aux_generator = BnG1::random(&mut rng);
        let circuit = CircuitDkg {
            secret: secrets.try_into().unwrap(),
            random: Value::known(random),
            public_key: public_key.try_into().unwrap(),
            aux_generator,
            window_size: 4,
            //   _marker: PhantomData::<Fr>,
        };

        let instance = vec![public_data];
        mock_prover_verify(&circuit, instance);

        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!("dimention: {:?}", dimension);
    }

    #[test]
    fn test_dkg_n_proof() {
        let (rns_base, _) = setup::<BnG1>(0);
        let rns_base = Rc::new(rns_base);

        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let g = BnG1::generator();

        // Generate a key pair for encryption
        let mut sks = vec![];
        let mut pks = vec![];

        for i in 0..NUMBER_OF_MEMBERS {
            let sk = BnScalar::random(&mut rng);
            let pk = (g * sk).to_affine();

            //      println!("\nsk = {:?}\n", sk);
            //      println!("\npk = {:?}\n", pk);

            sks.push(sk);
            pks.push(pk);
        }

        // Draw arandomness for encryption
        let random = BnScalar::random(&mut rng);
        let gr = (g * random).to_affine();

        let gr_point = Point::new(Rc::clone(&rns_base), gr);
        let mut public_data = gr_point.public();

        let mut secrets = vec![];
        let mut gss = vec![];

        let mut poseidon = Hash::<_, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init();

        for i in 0..NUMBER_OF_MEMBERS {
            //       println!("{} th loop", i);
            let secret = BnScalar::random(&mut rng);
            let gs = (g * secret).to_affine();
            //        println!("\nsecret = {:?}", secret);
            //        println!("\ngs = {:?}", gs);

            secrets.push(Value::known(secret));
            gss.push(gs);

            // Encrypt
            let pkr = (pks[i] * random).to_affine();
            let message = [mod_n::<BnG1>(pkr.x), mod_n::<BnG1>(pkr.y)];
            let key = poseidon.clone().hash(message);
            //   println!("\nrandom = {:?}", random);
            //   println!("\ngr = {:?}", gr);
            //   println!("\npkr = {:?}", pkr);
            //        println!("\nkey = {:?}", key);
            //        println!("\nsecret = {:?}", secret);
            let cipher = key + secret;
            //        println!("\ncipher = {:?}", cipher);

            let gs_point = Point::new(Rc::clone(&rns_base), gs);
            public_data.extend(gs_point.public());

            public_data.push(cipher);
        }

        let public_key: Vec<_> = pks.iter().map(|pk| Value::known(*pk)).collect();

        let aux_generator = BnG1::random(&mut rng);
        let circuit = CircuitDkg {
            secret: secrets.try_into().unwrap(),
            random: Value::known(random),
            public_key: public_key.try_into().unwrap(),
            aux_generator,
            window_size: 4,
            //   _marker: PhantomData::<Fr>,
        };

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
        let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");

        let vk_bytes = vk.to_bytes(SerdeFormat::RawBytes);
        println!("size of verification key (raw bytes) {}", vk_bytes.len());

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
