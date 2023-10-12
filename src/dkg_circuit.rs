#[cfg(feature = "g2chip")]
use crate::ecc_chip::FixedPoint2Chip;
use crate::ecc_chip::FixedPointChip;
use crate::grumpkin_chip::GrumpkinChip;
use crate::poseidon::P128Pow5T3Bn;
use crate::{BIT_LEN_LIMB, NUMBER_OF_LIMBS, POSEIDON_LEN, POSEIDON_RATE, POSEIDON_WIDTH};
use halo2_ecc::integer::rns::Rns;
#[cfg(feature = "g2chip")]
use halo2_ecc::integer::IntegerConfig;
use halo2_ecc::maingate::RegionCtx;
use halo2_ecc::EccConfig;
use halo2_gadgets::poseidon::{
    primitives::ConstantLength, Hash as PoseidonHash, Pow5Chip, Pow5Config,
};
use halo2_maingate::{
    MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
};
#[cfg(feature = "g2chip")]
use halo2wrong::curves::bn256::G2Affine as BnG2;
use halo2wrong::curves::{
    bn256::{Fq as BnBase, Fr as BnScalar, G1Affine as BnG1},
    ff::PrimeField,
    grumpkin::G1Affine as GkG1,
};
use halo2wrong::halo2::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error as PlonkError},
};
use rand_core::RngCore;

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
        let main_advices = main_gate_config.advices();
        let state = main_advices[0..POSEIDON_WIDTH].to_vec();
        let partial_sbox = main_advices[POSEIDON_WIDTH];

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

    #[cfg(feature = "g2chip")]
    fn integer_config(&self) -> IntegerConfig {
        IntegerConfig::new(self.range_config.clone(), self.main_gate_config.clone())
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
    window_size: usize,
    grumpkin_aux_generator: Value<GkG1>,
}

impl<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>
    CircuitDkg<THRESHOLD, NUMBER_OF_MEMBERS>
{
    pub fn new(
        coeffs: Vec<Value<BnScalar>>,
        random: Value<BnScalar>,
        public_keys: Vec<Value<GkG1>>,
        window_size: usize,
        grumpkin_aux_generator: Value<GkG1>,
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
            window_size,
            grumpkin_aux_generator,
        }
    }

    pub fn dummy(window_size: usize) -> Self {
        let coeffs: Vec<_> = (0..THRESHOLD).map(|_| Value::unknown()).collect();
        let random = Value::unknown();
        let public_keys: Vec<_> = (0..NUMBER_OF_MEMBERS).map(|_| Value::unknown()).collect();
        let grumpkin_aux_generator = Value::unknown();

        CircuitDkg {
            coeffs: coeffs
                .try_into()
                .expect("unable to convert coefficient vector"),
            random,
            public_keys: public_keys
                .try_into()
                .expect("unable to convert public key vector"),
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
        let mut fixed_chip =
            FixedPointChip::<BnG1, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_chip_config);

        #[cfg(feature = "g2chip")]
        let integer_config = config.integer_config();
        #[cfg(feature = "g2chip")]
        let mut fixed2_chip =
            FixedPoint2Chip::<BnBase, BnG2, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(integer_config);

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
            || "assign fixed point window table for bn256 chip",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let g = BnG1::generator();
                fixed_chip.assign_fixed_point(ctx, &g, self.window_size)?;

                #[cfg(feature = "g2chip")]
                let g2 = BnG2::generator();
                #[cfg(feature = "g2chip")]
                fixed2_chip.assign_fixed_point(ctx, &g2, self.window_size)?;

                Ok(())
            },
        )?;

        layouter.assign_region(
            || "assign aux values for grumpkin chip",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                grumpkin_chip.assign_aux_generator(ctx, self.grumpkin_aux_generator)?;
                grumpkin_chip.assign_aux_correction(ctx)?;
                Ok(())
            },
        )?;

        let ga = layouter.assign_region(
            || "region ecc mul g^a",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let ga = fixed_chip.mul(ctx, &a)?;
                // normalise for public inputs
                let ga = fixed_chip.normalize(ctx, &ga)?;

                Ok(ga)
            },
        )?;

        let mut instance_offset = 0usize;
        fixed_chip.expose_public(
            layouter.namespace(|| "cipher g^a"),
            ga,
            &mut instance_offset,
        )?;

        for i in 0..NUMBER_OF_MEMBERS {
            let gs = layouter.assign_region(
                || "region ecc mul g^s",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    // gs = g^s
                    let gs = fixed_chip.mul(ctx, &shares[i])?;
                    // normalise for public inputs
                    let gs = fixed_chip.normalize(ctx, &gs)?;
                    Ok(gs)
                },
            )?;

            fixed_chip.expose_public(layouter.namespace(|| "g^s"), gs, &mut instance_offset)?;
        }

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

        grumpkin_chip.expose_public(
            layouter.namespace(|| "cipher g^r"),
            gr,
            &mut instance_offset,
        )?;

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

            grumpkin_chip.expose_public(layouter.namespace(|| "pk"), pk, &mut instance_offset)?;

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

        // compute g2^a
        #[cfg(feature = "g2chip")]
        let g2a = layouter.assign_region(
            || "region mul",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let g2a = fixed2_chip.mul(ctx, &a)?;
                let g2a = fixed2_chip.normalize(ctx, &g2a)?;

                Ok(g2a)
            },
        )?;

        #[cfg(feature = "g2chip")]
        fixed2_chip.expose_public(layouter.namespace(|| "g2^a"), g2a, &mut instance_offset)?;

        config.config_range(&mut layouter)?;

        Ok(())
    }
}
