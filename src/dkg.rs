/*
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};

 */

use halo2wrong::halo2::{
    arithmetic::{CurveAffine, Field},
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};

use halo2wrong::curves::ff::PrimeField;

use std::marker::PhantomData;

//use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};
/*
use halo2wrong_ecc::halo2::{
    arithmetic::Field,
    plonk::{Advice, Column, ConstraintSystem, Instance},
};

 */

// integer::rns::Integer;
use halo2_ecc::integer::rns::Rns;
use halo2_ecc::integer::{
    rns::Integer, AssignedInteger, IntegerConfig, IntegerInstructions, Range,
};
use halo2_ecc::maingate::RegionCtx;
use halo2_ecc::{AssignedPoint, BaseFieldEccChip, EccConfig, GeneralEccChip, Point};
use halo2_gadgets::poseidon::primitives::ConstantLength;
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
//use halo2_integer::{rns::Integer, AssignedInteger, IntegerConfig, IntegerInstructions, Range};
use halo2_maingate::{
    MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
};

use halo2wrong::curves::bn256::{Fq as BnBase, Fr as BnScalar, G1Affine as BnG1};
use halo2wrong::halo2::plonk::Selector;
use halo2wrong::halo2::poly::Rotation;

use crate::poseidon::P128Pow5T3Bn;
use crate::{
    BIT_LEN_LIMB, NUMBER, NUMBER_OF_LIMBS, POSEIDON_LEN, POSEIDON_RATE, POSEIDON_WIDTH, THRESHOLD,
};

#[derive(Clone, Debug)]
pub struct CircuitDkgConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
    poseidon_config: Pow5Config<BnScalar, POSEIDON_WIDTH, POSEIDON_RATE>,
    secret: Column<Advice>,
    key: Column<Advice>,
    cipher: Column<Advice>,
    //    cipher: [Column<Instance>; 2],
    //    public: Column<Instance>,
    q_add: Selector,
}

impl CircuitDkgConfig {
    pub fn new(meta: &mut ConstraintSystem<BnScalar>) -> Self {
        //        let (rns_base, rns_scalar) = GeneralEccChip::<BnG1, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
        let rns = Rns::<BnBase, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::construct();
        let main_gate_config = MainGate::<BnScalar>::configure(meta);
        let overflow_bit_lens = rns.overflow_lengths();
        /*
        let mut overflow_bit_lens: Vec<usize> = vec![];
        overflow_bit_lens.extend(rns_base.overflow_lengths());
        overflow_bit_lens.extend(rns_scalar.overflow_lengths());
         */
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

        // encryption (addition) configure
        let secret = meta.advice_column();
        let key = meta.advice_column();
        let cipher = meta.advice_column();
        //       let public = meta.instance_column();
        meta.enable_equality(secret);
        meta.enable_equality(key);
        meta.enable_equality(cipher);
        //        meta.enable_equality(public);

        let q_add = meta.selector();

        meta.create_gate("add", |meta| {
            //
            // secret | key | cipher | selector
            //   a      b        c       s
            //
            let s = meta.query_selector(q_add);
            let a = meta.query_advice(secret, Rotation::cur());
            let b = meta.query_advice(key, Rotation::cur());
            let c = meta.query_advice(cipher, Rotation::cur());
            vec![s * (a + b - c)]
        });

        CircuitDkgConfig {
            main_gate_config,
            range_config,
            poseidon_config,
            secret,
            key,
            cipher,
            //         public,
            q_add,
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
    secret: Value<BnScalar>,
    random: Value<BnScalar>,
    public_key: Value<BnG1>,

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
        //   let mut ecc_chip = GeneralEccChip::<BnG1, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);
        let mut ecc_chip =
            BaseFieldEccChip::<BnG1, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);
        let main_gate = MainGate::<BnScalar>::new(config.main_gate_config.clone());
        //  let main_gate = ecc_chip.main_gate();

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

        //     let scalar_chip = ecc_chip.scalar_field_chip();

        let (s, gs, gr, pkr) = layouter.assign_region(
            || "region ecc mul",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                //   let s = ecc_chip.new_unassigned_scalar(self.secret);
                //   let r = ecc_chip.new_unassigned_scalar(self.random);

                //  let s_integer = scalar_chip.assign_integer(ctx, s, Range::Remainder)?;
                //  let r_integer = scalar_chip.assign_integer(ctx, r, Range::Remainder)?;
                let s = main_gate.assign_value(ctx, self.secret)?;
                let r = main_gate.assign_value(ctx, self.random)?;

                let g_assigned = ecc_chip.assign_point(ctx, Value::known(BnG1::generator()))?;
                let pk_assigned = ecc_chip.assign_point(ctx, self.public_key)?;

                // gs = g^s, gr = g^r, pkr = pk^r
                let gs = ecc_chip.mul(ctx, &g_assigned, &s, self.window_size)?;
                let gr = ecc_chip.mul(ctx, &g_assigned, &r, self.window_size)?;
                let pkr = ecc_chip.mul(ctx, &pk_assigned, &r, self.window_size)?;

                let gs = ecc_chip.normalize(ctx, &gs)?;
                let gr = ecc_chip.normalize(ctx, &gr)?;
                let pkr = ecc_chip.normalize(ctx, &pkr)?;
                Ok((s, gs, gr, pkr))
            },
        )?;

        println!("\ngs in circuit = {:?}", gs);

        let poseidon_chip = Pow5Chip::construct(config.poseidon_config.clone());
        let message = [pkr.x().native().clone(), pkr.y().native().clone()];

        let hasher = PoseidonHash::<
            _,
            _,
            P128Pow5T3Bn,
            ConstantLength<POSEIDON_LEN>,
            POSEIDON_WIDTH,
            POSEIDON_RATE,
        >::init(poseidon_chip, layouter.namespace(|| "init"))?;
        let key = hasher.hash(layouter.namespace(|| "hash"), message)?;
        println!("\nkey in circuit = {:?}", key.value());

        let cipher = layouter.assign_region(
            || "region add",
            |mut region| {
                config.q_add.enable(&mut region, 0)?;

                //  region.assign_advice(|| "secret", config.secret, 0, || self.secret)?;
                //   let s_cell = s_integer.native();
                s.copy_advice(|| "copy secret", &mut region, config.secret, 0)?;
                key.copy_advice(|| "copy session key", &mut region, config.key, 0)?;

                //   println!("\ns value = {:?}", s.value());

                let cipher = region.assign_advice(
                    || "cipher",
                    config.cipher,
                    0,
                    || key.value() + self.secret,
                )?;

                Ok(cipher)
            },
        )?;

        println!("\ncipher in circuit = {:?}", cipher.value());

        ecc_chip.expose_public(layouter.namespace(|| "g^s"), gs, 0)?;
        ecc_chip.expose_public(layouter.namespace(|| "cipher g^r"), gr, 8)?;
        main_gate.expose_public(layouter.namespace(|| "cipher main"), cipher, 16)?;

        //   layouter.constrain_instance(cipher_cell.cell(), config.public, 0)?;

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

    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};
    use std::rc::Rc;

    use super::*;
    use crate::poseidon::P128Pow5T3Bn;
    use crate::utils::{mod_n, rns, setup};

    #[test]
    fn test_ecc() {
        let g = BnG1::generator();

        let mut rng = ChaCha20Rng::seed_from_u64(42);

        // Generate a key pair
        let sk = BnScalar::random(&mut rng);
        let pk = (g * sk).to_affine();

        println!("sk = {:?}", sk);

        // Draw arandomness
        let secret = BnScalar::random(&mut rng);
        let r = BnScalar::random(&mut rng);

        // Encrypt
        let gr = (g * r).to_affine();
        let pkr = (pk * r).to_affine();

        let message = [mod_n::<BnG1>(pkr.x), mod_n::<BnG1>(pkr.y)];
        let hasher = Hash::<BnScalar, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init();
        let key = hasher.hash(message.into());
        let c = key + secret;
        let cipher = (gr, c);

        // Decrypt
        let pkr_prime = (cipher.0 * sk).to_affine();
        let message_prime = [mod_n::<BnG1>(pkr_prime.x), mod_n::<BnG1>(pkr_prime.y)];
        let key_prime = Hash::<BnScalar, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init()
            .hash(message_prime.into());
        let secret_prime = c - key_prime;

        assert_eq!(secret, secret_prime)
    }

    #[test]
    fn test_dkg_circuit() {
        let (rns_base, _) = setup::<BnG1>(0);
        let rns_base = Rc::new(rns_base);

        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let g = BnG1::generator();

        // Generate a key pair
        let sk = BnScalar::random(&mut rng);
        let pk = (g * sk).to_affine();

        println!("\nsk = {:?}\n", sk);
        println!("\npk = {:?}\n", pk);

        // Draw arandomness
        let secret = BnScalar::random(&mut rng);
        let random = BnScalar::random(&mut rng);

        let gs = (g * secret).to_affine();
        println!("\ngs = {:?}", gs);

        // Encrypt
        let gr = (g * random).to_affine();
        let pkr = (pk * random).to_affine();

        let message = [mod_n::<BnG1>(pkr.x), mod_n::<BnG1>(pkr.y)];
        let key = Hash::<_, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init().hash(message);
        //   println!("\nrandom = {:?}", random);
        //   println!("\ngr = {:?}", gr);
        //   println!("\npkr = {:?}", pkr);
        println!("\nkey = {:?}", key);
        println!("\nsecret = {:?}", secret);
        let cipher = key + secret;
        println!("\ncipher = {:?}", cipher);

        let gs_point = Point::new(Rc::clone(&rns_base), gs);
        let mut public_data = gs_point.public();
        let c0 = Point::new(Rc::clone(&rns_base), gr);
        //   let mut public_data = c0.public();
        public_data.extend(c0.public());
        let c1 = Point::new(Rc::clone(&rns_base), pkr);
        //  public_data.extend(c1.public());

        // todo: add poseidon hash

        let aux_generator = BnG1::random(&mut rng);
        let circuit = CircuitDkg {
            secret: Value::known(secret),
            random: Value::known(random),
            public_key: Value::known(pk),
            aux_generator,
            window_size: 4,
            //   _marker: PhantomData::<Fr>,
        };
        public_data.push(cipher);
        let instance = vec![public_data];
        mock_prover_verify(&circuit, instance);

        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!("dimention: {:?}", dimension);
    }
}
