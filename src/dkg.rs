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
use halo2_ecc::integer::{
    rns::Integer, AssignedInteger, IntegerConfig, IntegerInstructions, Range,
};
use halo2_ecc::maingate::RegionCtx;
use halo2_ecc::{AssignedPoint, EccConfig, GeneralEccChip, Point};
use halo2_gadgets::poseidon::primitives::ConstantLength;
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
//use halo2_integer::{rns::Integer, AssignedInteger, IntegerConfig, IntegerInstructions, Range};
use halo2_maingate::{
    MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
};

use halo2wrong::curves::bn256::{Fr as BnScalar, G1Affine as BnG1};
use halo2wrong::halo2::plonk::Selector;
use halo2wrong::halo2::poly::Rotation;

use crate::poseidon::P128Pow5T3Bn;

const BIT_LEN_LIMB: usize = 68;
const NUMBER_OF_LIMBS: usize = 4;
const POSEIDON_WIDTH: usize = 3;
const POSEIDON_RATE: usize = 2;
const POSEIDON_LEN: usize = 2;

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
        let (rns_base, rns_scalar) =
            GeneralEccChip::<BnG1, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
        let main_gate_config = MainGate::<BnScalar>::configure(meta);
        let mut overflow_bit_lens: Vec<usize> = vec![];
        overflow_bit_lens.extend(rns_base.overflow_lengths());
        overflow_bit_lens.extend(rns_scalar.overflow_lengths());
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

    pub fn config_range(&self, layouter: &mut impl Layouter<BnScalar>) -> Result<(), Error> {
        let range_chip = RangeChip::<BnScalar>::new(self.range_config.clone());
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
        let mut ecc_chip =
            GeneralEccChip::<BnG1, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);

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

        let scalar_chip = ecc_chip.scalar_field_chip();

        let (c0, c1) = layouter.assign_region(
            || "region ecc mul",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                //      let s = ecc_chip.new_unassigned_scalar(self.secret);
                let r = ecc_chip.new_unassigned_scalar(self.random);

                //      let s_integer = scalar_chip.assign_integer(ctx, s, Range::Remainder)?;
                let r_integer = scalar_chip.assign_integer(ctx, r, Range::Remainder)?;

                let g_assigned = ecc_chip.assign_point(ctx, Value::known(BnG1::generator()))?;
                let pk_assigned = ecc_chip.assign_point(ctx, self.public_key)?;

                // c0 = g^r, c1 = pk^r
                let c0 = ecc_chip.mul(ctx, &g_assigned, &r_integer, self.window_size)?;
                let c1 = ecc_chip.mul(ctx, &pk_assigned, &r_integer, self.window_size)?;

                let c0 = ecc_chip.normalize(ctx, &c0)?;
                let c1 = ecc_chip.normalize(ctx, &c1)?;
                Ok((c0, c1))
            },
        )?;

        let poseidon_chip = Pow5Chip::construct(config.poseidon_config.clone());
        let message = [c1.x().native().clone(), c1.y().native().clone()];

        let hasher = PoseidonHash::<
            _,
            _,
            P128Pow5T3Bn,
            ConstantLength<POSEIDON_LEN>,
            POSEIDON_WIDTH,
            POSEIDON_RATE,
        >::init(poseidon_chip, layouter.namespace(|| "init"))?;
        let key_cell = hasher.hash(layouter.namespace(|| "hash"), message)?;
        println!("\nkey in circuit = {:?}", key_cell.value());

        let cipher_cell = layouter.assign_region(
            || "region native add",
            |mut region| {
                config.q_add.enable(&mut region, 0)?;

                region.assign_advice(|| "secret", config.secret, 0, || self.secret)?;
                //   let s_cell = s_integer.native();
                //    s_cell.copy_advice(|| "copy secret", &mut region, config.secret, 0)?;
                key_cell.copy_advice(|| "copy session key", &mut region, config.key, 0)?;

                //     println!("\ns_cell value = {:?}", s_cell.value());

                let cipher = key_cell.value() + self.secret;
                let cipher_cell = region.assign_advice(|| "cipher", config.cipher, 0, || cipher)?;

                Ok(cipher_cell)
            },
        )?;

        println!("\ncipher in circuit = {:?}", cipher_cell.value());

        ecc_chip.expose_public(layouter.namespace(|| "cipher g^r"), c0, 0)?;
        //   ecc_chip.expose_public(layouter.namespace(|| "cipher"), c1, 8)?;
        //   ecc_chip.expose_public(layouter.namespace(|| "symmetric key"), )

        ecc_chip.main_gate().expose_public(
            layouter.namespace(|| "cipher final"),
            cipher_cell,
            8,
        )?;

        //   layouter.constrain_instance(cipher_cell.cell(), config.public, 0)?;

        // todo: move?
        config.config_range(&mut layouter)?;

        Ok(())
    }
}

///////todo
/*
#[derive(Clone, Debug)]
pub struct Cipher<
    W: PrimeField,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    pub r: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    pub s: Integer<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

pub struct AssignedCipher<
    W: PrimeField,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    pub r: AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    pub s: AssignedInteger<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

pub struct AssignedPublicKey<
    W: PrimeField,
    N: PrimeField,
    const NUMBER_OF_LIMBS: usize,
    const BIT_LEN_LIMB: usize,
> {
    pub point: AssignedPoint<W, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

#[derive(Debug, Clone)]
pub struct EncryptConfig<F: Field> {
    s: Column<Advice>,
    r: Column<Advice>,
    pk: Column<Instance>,
    cipher: Column<Instance>,
    _marker: PhantomData<F>,
}

 */

#[cfg(test)]
mod tests {
    use halo2_ecc::integer::rns::Rns;
    use halo2_ecc::integer::NUMBER_OF_LOOKUP_LIMBS;
    use std::rc::Rc;
    //   use std::hash::Hash;
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};
    // use halo2wrong::curves::bn256::{Fr as , G1Affine};
    use halo2wrong::curves::group::Curve;
    use halo2wrong::curves::CurveAffine;
    use halo2wrong::utils::{big_to_fe, fe_to_big, mock_prover_verify, DimensionMeasurement};
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};

    use super::*;
    use crate::poseidon::P128Pow5T3Bn;
    //   use halo2wrong_ecc::curves::bn256::{Bn256, Fr, G1Affine};

    fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
        let x_big = fe_to_big(x);
        big_to_fe(x_big)
    }

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

    #[allow(clippy::type_complexity)]
    fn setup<
        C: CurveAffine,
        N: PrimeField,
        const NUMBER_OF_LIMBS: usize,
        const BIT_LEN_LIMB: usize,
    >(
        k_override: u32,
    ) -> (
        Rns<C::Base, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        Rns<C::Scalar, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        u32,
    ) {
        let (rns_base, rns_scalar) = GeneralEccChip::<C, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
        let bit_len_lookup = BIT_LEN_LIMB / NUMBER_OF_LOOKUP_LIMBS;
        let mut k: u32 = (bit_len_lookup + 1) as u32;
        if k_override != 0 {
            k = k_override;
        }
        (rns_base, rns_scalar, k)
    }

    #[test]
    fn test_dkg_circuit() {
        let (rns_base, _, _) = setup::<BnG1, BnScalar, NUMBER_OF_LIMBS, BIT_LEN_LIMB>(0);
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

        // Encrypt
        let gr = (g * random).to_affine();
        let pkr = (pk * random).to_affine();

        let message = [mod_n::<BnG1>(pkr.x), mod_n::<BnG1>(pkr.y)];
        let key = Hash::<_, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init().hash(message);
        //   println!("\nrandom = {:?}\n", random);
        //   println!("\ngr = {:?}\n", gr);
        //   println!("\npkr = {:?}\n", pkr);
        println!("\nkey = {:?}", key);
        println!("\nsecret = {:?}", secret);
        let cipher = key + secret;
        println!("\ncipher = {:?}", cipher);

        let c0 = Point::new(Rc::clone(&rns_base), gr);
        let mut public_data = c0.public();
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
