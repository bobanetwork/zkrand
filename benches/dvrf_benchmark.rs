use criterion::{criterion_group, Criterion};

mod dvrf_benches {
    use super::*;
    use blake2b_simd::blake2b;
    use halo2wrong::curves::bn256::{Fr as BnScalar, G1Affine as BnG1, G2Affine as BnG2};
    use halo2wrong::curves::group::{Curve, GroupEncoding};
    use halo2wrong::halo2::arithmetic::Field;
    use rand_core::OsRng;
    use zkdvrf::{
        combine_partial_evaluations, get_shares, hash_to_curve_bn, keygen, DkgShareKey,
        PseudoRandom, EVAL_PREFIX,
    };

    // partial evaluation time independent of the values of threshold and number of members
    fn partial_evaluate(c: &mut Criterion) {
        let mut rng = OsRng;

        let index = 1;
        let (sk, vk) = keygen(&mut rng);
        let key = DkgShareKey::<4, 6>::new(index, sk, vk);
        let x = b"the first random 20230703";

        c.bench_function("dvrf partial evaluation", move |b| {
            b.iter(|| key.evaluate(x, &mut rng))
        });
    }

    fn combine<const THRESHOLD: usize, const NUMBER_OF_MEMBERS: usize>(c: &mut Criterion) {
        let mut rng = OsRng;
        // simplified setup only used for benchmark
        let g = BnG1::generator();
        let coeffs: Vec<_> = (0..THRESHOLD).map(|_| BnScalar::random(&mut rng)).collect();
        let shares = get_shares::<THRESHOLD, NUMBER_OF_MEMBERS>(&coeffs);
        let keys: Vec<_> = shares
            .iter()
            .enumerate()
            .map(|(i, s)| {
                DkgShareKey::<THRESHOLD, NUMBER_OF_MEMBERS>::new(i + 1, *s, (g * s).to_affine())
            })
            .collect();
        let vks: Vec<_> = keys.iter().map(|key| key.get_verification_key()).collect();

        let input = b"test first random";

        let evals: Vec<_> = keys
            .iter()
            .map(|key| key.evaluate(input, &mut rng))
            .collect();

        let res = evals
            .iter()
            .zip(vks.iter())
            .all(|(e, vk)| e.verify(input, vk).is_ok());

        assert!(res);

        let name = format!("dvrf combine partial evaluation ({THRESHOLD}, {NUMBER_OF_MEMBERS})");
        c.bench_function(name.as_str(), move |b| {
            b.iter(|| combine_partial_evaluations(&evals[0..THRESHOLD]).unwrap());
        });
    }

    fn partial_verify(c: &mut Criterion) {
        let mut rng = OsRng;

        let index = 1;
        let (sk, vk) = keygen(&mut rng);
        // verification time of partial evaluation independent of the values of threshold and number of members
        let key = DkgShareKey::<4, 6>::new(index, sk, vk);
        let input = b"the first random 20230703";
        let sigma = key.evaluate(input, &mut rng);

        c.bench_function("dvrf partial evaluation verify", move |b| {
            b.iter(|| sigma.verify(input, &vk).unwrap())
        });
    }

    fn pseudo_random_verify(c: &mut Criterion) {
        // simplified setup only used for benchmark
        let mut rng = OsRng;
        let (a, _) = keygen(&mut rng);
        let g2 = BnG2::generator();
        let gpk = (g2 * a).to_affine();

        let input = b"the first random 20230703";
        let hasher = hash_to_curve_bn(EVAL_PREFIX);
        let h: BnG1 = hasher(input).to_affine();

        let proof = (h * a).to_affine();
        let value = blake2b(proof.to_bytes().as_ref()).as_bytes().to_vec();
        let pr = PseudoRandom::new(proof, value);

        c.bench_function("dvrf pseudorandom verification", move |b| {
            b.iter(|| pr.verify(input, &gpk).unwrap())
        });
    }

    criterion_group! {
        name = dvrf_benches;
        config = Criterion::default();
        targets =
            partial_evaluate,
            combine::<5,9>,
            combine::<11,21>,
            combine::<22,43>,
            combine::<45,88>,
            combine::<89,177>,
            partial_verify,
            pseudo_random_verify,
    }
}

criterion::criterion_main!(dvrf_benches::dvrf_benches);
