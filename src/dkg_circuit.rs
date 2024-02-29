use crate::dkg::DkgConfig;
#[cfg(feature = "g2chip")]
use crate::ecc_chip::FixedPoint2Chip;
use crate::ecc_chip::FixedPointChip;
use crate::grumpkin_chip::GrumpkinChip;
use crate::poseidon::P128Pow5T3Bn;
use crate::{
    BIT_LEN_LIMB, NUMBER_OF_LIMBS, POSEIDON_LEN, POSEIDON_RATE, POSEIDON_WIDTH, WINDOW_SIZE,
    WRAP_LEN,
};
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

#[derive(Clone, Debug)]
pub struct DkgCircuitConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
    poseidon_config: Pow5Config<BnScalar, POSEIDON_WIDTH, POSEIDON_RATE>,
}

impl DkgCircuitConfig {
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

        DkgCircuitConfig {
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
pub struct DkgCircuit {
    dkg_config: DkgConfig,
    coeffs: Vec<Value<BnScalar>>,
    random: Value<BnScalar>,
    public_keys: Vec<Value<GkG1>>,
    grumpkin_aux_generator: Value<GkG1>,
}

impl DkgCircuit {
    pub fn new(
        dkg_config: DkgConfig,
        coeffs: Vec<Value<BnScalar>>,
        random: Value<BnScalar>,
        public_keys: Vec<Value<GkG1>>,
        grumpkin_aux_generator: Value<GkG1>,
    ) -> Self {
        assert_eq!(coeffs.len(), dkg_config.threshold());
        assert_eq!(public_keys.len(), dkg_config.number_of_members());

        DkgCircuit {
            dkg_config,
            coeffs,
            random,
            public_keys,
            grumpkin_aux_generator,
        }
    }

    pub fn dummy(dkg_config: DkgConfig) -> Self {
        let coeffs: Vec<_> = (0..dkg_config.threshold())
            .map(|_| Value::unknown())
            .collect();
        let random = Value::unknown();
        let public_keys: Vec<_> = (0..dkg_config.number_of_members())
            .map(|_| Value::unknown())
            .collect();
        let grumpkin_aux_generator = Value::unknown();

        DkgCircuit {
            dkg_config,
            coeffs,
            random,
            public_keys,
            grumpkin_aux_generator,
        }
    }

    pub fn threshold(&self) -> usize {
        self.dkg_config.threshold()
    }

    pub fn number_of_members(&self) -> usize {
        self.dkg_config.number_of_members()
    }
}

impl Circuit<BnScalar> for DkgCircuit {
    type Config = DkgCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<BnScalar>) -> Self::Config {
        DkgCircuitConfig::new(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<BnScalar>,
    ) -> Result<(), PlonkError> {
        config.config_range(&mut layouter)?;

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
                for j in 1..self.threshold() {
                    s0 = main_gate.add(ctx, &s0, &coeffs[j])?;
                }
                shares.push(s0);

                for i in 2..=self.number_of_members() {
                    let ii = BnScalar::from(i as u64);
                    let x = main_gate.assign_constant(ctx, ii)?;
                    let mut s = coeffs[self.threshold() - 1].clone();
                    for j in (0..self.threshold() - 1).rev() {
                        s = main_gate.mul_add(ctx, &s, &x, &coeffs[j])?;
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
                fixed_chip.assign_fixed_point(ctx, &g, WINDOW_SIZE)?;

                #[cfg(feature = "g2chip")]
                let g2 = BnG2::generator();
                #[cfg(feature = "g2chip")]
                fixed2_chip.assign_fixed_point(ctx, &g2, WINDOW_SIZE)?;

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
        let assigned_base = fixed_chip.expose_public_optimal(
            layouter.namespace(|| "bn256 G1 point g^a"),
            ga,
            WRAP_LEN,
            None,
            &mut instance_offset,
        )?;

        for i in 0..self.number_of_members() {
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

            fixed_chip.expose_public_optimal(
                layouter.namespace(|| "bn256 G1 point g^s"),
                gs,
                WRAP_LEN,
                Some(assigned_base.clone()),
                &mut instance_offset,
            )?;
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
        fixed2_chip.expose_public_optimal(
            layouter.namespace(|| "bn256 G2 point g2^a"),
            g2a,
            WRAP_LEN,
            Some(assigned_base),
            &mut instance_offset,
        )?;

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

        let mut assigned_pks = vec![];
        for i in 0..self.number_of_members() {
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

            assigned_pks.push(pk);

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

        for pk in assigned_pks.into_iter() {
            grumpkin_chip.expose_public(layouter.namespace(|| "pk"), pk, &mut instance_offset)?;
        }

        Ok(())
    }
}
