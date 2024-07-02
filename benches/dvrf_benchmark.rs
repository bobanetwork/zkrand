use criterion::{criterion_group, Criterion};

mod dvrf_benches {
    use super::*;
    use halo2wrong::curves::bn256::{Fr as BnScalar, G1Affine as BnG1, G2Affine as BnG2};
    use halo2wrong::curves::group::{Curve, GroupEncoding};
    use halo2wrong::halo2::arithmetic::Field;
    use rand_core::OsRng;
    use sha3::{Digest, Keccak256};
    use zkrand::dkg::DkgConfig;
    use zkrand::{
        combine_partial_evaluations, hash_to_curve_bn, keygen, shares, DkgShareKey, PseudoRandom,
        EVAL_PREFIX,
    };

    // partial evaluation time independent of the values of threshold and number of members
    fn partial_evaluate(c: &mut Criterion) {
        let mut rng = OsRng;

        let index = 1;
        let (sk, vk) = keygen(&mut rng);
        let key = DkgShareKey::new(index, sk, vk);
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
        let shares = shares(NUMBER_OF_MEMBERS, &coeffs);
        let keys: Vec<_> = shares
            .iter()
            .enumerate()
            .map(|(i, s)| DkgShareKey::new(i + 1, *s, (g * s).to_affine()))
            .collect();
        let vks: Vec<_> = keys.iter().map(|key| key.verify_key()).collect();

        let input = b"test first random";

        let evals: Vec<_> = keys
            .iter()
            .map(|key| key.evaluate(input, &mut rng))
            .collect();

        let dkg_config = DkgConfig::new(THRESHOLD, NUMBER_OF_MEMBERS).unwrap();
        let res = evals
            .iter()
            .zip(vks.iter())
            .all(|(e, vk)| e.verify(&dkg_config, input, vk).is_ok());

        assert!(res);

        let name = format!("dvrf combine partial evaluation ({THRESHOLD}, {NUMBER_OF_MEMBERS})");
        c.bench_function(name.as_str(), move |b| {
            b.iter(|| combine_partial_evaluations(&dkg_config, &evals[0..THRESHOLD]).unwrap());
        });
    }

    fn partial_verify(c: &mut Criterion) {
        let mut rng = OsRng;

        let index = 1;
        let (sk, vk) = keygen(&mut rng);
        // verification time of partial evaluation independent of the values of threshold and number of members
        let key = DkgShareKey::new(index, sk, vk);
        let input = b"the first random 20230703";
        let sigma = key.evaluate(input, &mut rng);

        let dkg_config = DkgConfig::new(4, 6).unwrap();
        c.bench_function("dvrf partial evaluation verify", move |b| {
            b.iter(|| sigma.verify(&dkg_config, input, &vk).unwrap())
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
        // reverse order to match solidity version
        let mut bytes = proof.y.to_bytes().to_vec();
        bytes.extend(proof.x.to_bytes());
        bytes.reverse();

        let value = Keccak256::new().chain_update(bytes).finalize().to_vec();
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
            combine::<3,5>,
            combine::<9,16>,
            combine::<20,38>,
            combine::<42,83>,
            combine::<86,171>,
            partial_verify,
            pseudo_random_verify,
    }
}

criterion::criterion_main!(dvrf_benches::dvrf_benches);
