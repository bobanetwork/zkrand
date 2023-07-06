use halo2_gadgets::poseidon::primitives::{Mds, Spec};
use halo2wrong::curves::bn256::Fr;
use halo2wrong::halo2::arithmetic::Field;

mod bn256;
use bn256::{MDS, MDS_INV, ROUND_CONSTANTS};

// poseidon on bn256
#[derive(Debug, Clone, Copy)]
pub struct P128Pow5T3Bn;

impl Spec<Fr, 3, 2> for P128Pow5T3Bn {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fr) -> Fr {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        unimplemented!()
    }

    fn constants() -> (Vec<[Fr; 3]>, Mds<Fr, 3>, Mds<Fr, 3>) {
        (ROUND_CONSTANTS.to_vec(), *MDS, *MDS_INV)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash};
    use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip, Pow5Config};
    use halo2wrong::curves::bn256::Fr as Fp;
    use halo2wrong::halo2::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2wrong::halo2::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance};
    use halo2wrong::utils::{mock_prover_verify, DimensionMeasurement};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::marker::PhantomData;

    //https://github.com/privacy-scaling-explorations/halo2/blob/v2023_04_20/halo2_gadgets/benches/poseidon.rs
    #[derive(Clone, Copy)]
    struct HashCircuit<S, const WIDTH: usize, const RATE: usize, const L: usize>
    where
        S: Spec<Fp, WIDTH, RATE> + Clone + Copy,
    {
        message: Value<[Fp; L]>,
        _spec: PhantomData<S>,
    }

    #[derive(Debug, Clone)]
    struct MyConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
        input: [Column<Advice>; L],
        expected: Column<Instance>,
        poseidon_config: Pow5Config<Fp, WIDTH, RATE>,
    }

    impl<S, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<Fp>
        for HashCircuit<S, WIDTH, RATE, L>
    where
        S: Spec<Fp, WIDTH, RATE> + Copy + Clone,
    {
        type Config = MyConfig<WIDTH, RATE, L>;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self {
                message: Value::unknown(),
                _spec: PhantomData,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
            let expected = meta.instance_column();
            meta.enable_equality(expected);
            let partial_sbox = meta.advice_column();

            let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
            let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

            meta.enable_constant(rc_b[0]);

            Self::Config {
                input: state[..RATE].try_into().unwrap(),
                expected,
                poseidon_config: Pow5Chip::configure::<S>(
                    meta,
                    state.try_into().unwrap(),
                    partial_sbox,
                    rc_a.try_into().unwrap(),
                    rc_b.try_into().unwrap(),
                ),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = Pow5Chip::construct(config.poseidon_config.clone());

            let message = layouter.assign_region(
                || "load message",
                |mut region| {
                    let message_word = |i: usize| {
                        let value = self.message.map(|message_vals| message_vals[i]);
                        region.assign_advice(
                            || format!("load message_{}", i),
                            config.input[i],
                            0,
                            || value,
                        )
                    };

                    let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
                    Ok(message?.try_into().unwrap())
                },
            )?;

            let hasher = PoseidonHash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
                chip,
                layouter.namespace(|| "init"),
            )?;
            let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

            layouter.constrain_instance(output.cell(), config.expected, 0)
        }
    }

    /*
       #[derive(Debug, Clone, Copy)]
       struct MySpec<const WIDTH: usize, const RATE: usize>;

       impl<const WIDTH: usize, const RATE: usize> Spec<Fp, WIDTH, RATE> for MySpec<WIDTH, RATE> {
           fn full_rounds() -> usize {
               8
           }

           fn partial_rounds() -> usize {
               56
           }

           fn sbox(val: Fp) -> Fp {
               val.pow_vartime(&[5])
           }

           fn secure_mds() -> usize {
               0
           }

           fn constants() -> (Vec<[Fp; WIDTH]>, Mds<Fp, WIDTH>, Mds<Fp, WIDTH>) {
               generate_constants::<_, Self, WIDTH, RATE>()
           }
       }


       const K: u32 = 7;

    */

    #[test]
    fn poseidon_hash() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let message = [Fp::random(&mut rng), Fp::random(&mut rng)];
        let output = Hash::<_, P128Pow5T3Bn, ConstantLength<2>, 3, 2>::init().hash(message);

        let circuit = HashCircuit::<P128Pow5T3Bn, 3, 2, 2> {
            message: Value::known(message),
            _spec: PhantomData,
        };
        let dimension = DimensionMeasurement::measure(&circuit).unwrap();
        println!("dimension = {:?}", dimension);

        mock_prover_verify(&circuit, vec![vec![output]]);
    }
}
