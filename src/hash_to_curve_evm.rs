#![allow(clippy::op_ref)]

use halo2_ecc::halo2::arithmetic::CurveExt;
use halo2wrong::curves::bn256::{Fq, G1};
use halo2wrong::curves::ff::Field;
use sha3::{Digest, Keccak256};
use subtle::ConditionallySelectable;

/// (q-1)/2 = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3
const Q2: Fq = Fq::from_raw([
    0x9e10460b6c3e7ea3,
    0xcbc0b548b438e546,
    0xdc2822db40c0ac2e,
    0x183227397098d014,
]);

/// -1 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46
const MINUS_ONE: Fq = Fq::from_raw([
    0x3c208c16d87cfd46,
    0x97816a916871ca8d,
    0xb85045b68181585d,
    0x30644e72e131a029,
]);

/// R = 2^256 mod q = 0xe0a77c19a07df2f666ea36f7879462c0a78eb28f5c70b3dd35d438dc58f0d9d
const R: Fq = Fq::from_raw([
    0xd35d438dc58f0d9d,
    0x0a78eb28f5c70b3d,
    0x666ea36f7879462c,
    0x0e0a77c19a07df2f,
]);

/// C1 = (-1 + sqrt(-3))/2 = 0x000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe
const C1: Fq = Fq::from_raw([
    0x5763473177fffffe,
    0xd4f263f1acdb5c4f,
    0x59e26bcea0d48bac,
    0x0000000000000000,
]);

/// C2 = sqrt(-3) = 0x0000000000000000b3c4d79d41a91759a9e4c7e359b6b89eaec68e62effffffd
const C2: Fq = Fq::from_raw([
    0xaec68e62effffffd,
    0xa9e4c7e359b6b89e,
    0xb3c4d79d41a91759,
    0x0000000000000000,
]);

/// C3 = 1/3 = 0x2042def740cbc01bd03583cf0100e593ba56470b9af68708d2c05d6490535385
const C3: Fq = Fq::from_raw([
    0xd2c05d6490535385,
    0xba56470b9af68708,
    0xd03583cf0100e593,
    0x2042def740cbc01b,
]);

pub fn from_be_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    let limb0 = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
    let limb1 = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
    let limb2 = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    let limb3 = u64::from_be_bytes(bytes[0..8].try_into().unwrap());

    [limb0, limb1, limb2, limb3]
}

fn hash_to_field_evm(domain_prefix: &str, message: &[u8], buf: &mut [Fq; 2]) {
    let domain = domain_prefix.as_bytes();
    let domain_len_bytes = domain.len().to_be_bytes().to_vec();
    // pad domain length to 32 bytes
    let domain_len_bytes: Vec<_> = vec![0u8; 32 - domain_len_bytes.len()]
        .into_iter()
        .chain(domain_len_bytes)
        .collect();

    let msg_len_bytes = message.len().to_be_bytes().to_vec();
    // pad message length to 32 bytes
    let msg_len_bytes: Vec<_> = vec![0u8; 32 - msg_len_bytes.len()]
        .into_iter()
        .chain(msg_len_bytes)
        .collect();

    let hash0 = Keccak256::new()
        .chain_update([0u8, 1u8])
        .chain_update(domain_len_bytes)
        .chain_update(domain)
        .chain_update(msg_len_bytes)
        .chain_update(message)
        .finalize()
        .to_vec();

    let hash1 = Keccak256::new()
        .chain_update([2u8, 3u8])
        .chain_update(&hash0)
        .finalize()
        .to_vec();
    let hash2 = Keccak256::new()
        .chain_update([4u8, 5u8])
        .chain_update(&hash1)
        .finalize()
        .to_vec();
    let hash3 = Keccak256::new()
        .chain_update([6u8, 7u8])
        .chain_update(&hash2)
        .finalize()
        .to_vec();

    let t0 = Fq::from_raw(from_be_bytes(&hash0.try_into().unwrap()));
    let t1 = Fq::from_raw(from_be_bytes(&hash1.try_into().unwrap()));
    let t2 = Fq::from_raw(from_be_bytes(&hash2.try_into().unwrap()));
    let t3 = Fq::from_raw(from_be_bytes(&hash3.try_into().unwrap()));

    buf[0] = t0 * R + t1;
    buf[1] = t2 * R + t3;
}

fn sign(t: Fq) -> Fq {
    if t <= Q2 {
        return Fq::ONE;
    }

    return MINUS_ONE;
}

fn map_to_curve_evm(t: Fq) -> G1 {
    let t_sign = sign(t);
    // s = (t^2 + 4)^3
    let t_square = t.square();
    let t4 = t_square.square();
    let r = t_square + Fq::from(4u64);
    let r_square = r.square();
    let s = r * r_square;

    // alpha = 1/(t^2 * (t^2 + 4))
    let alpha = (t_square * r).invert().unwrap_or(Fq::ZERO);

    // x1 = C1 - C2 * t^4 * alpha
    let x1 = C1 - C2 * t4 * alpha;
    // x2 = -1 - x1
    let x2 = -(x1 + Fq::ONE);
    // x3 = 1 - s * alpha/3
    let x3 = Fq::ONE - s * alpha * C3;

    let u1 = x1.cube() + Fq::from(3u64);
    let y1 = u1.sqrt();
    let e1 = y1.is_some();

    let u2 = x2.cube() + Fq::from(3u64);
    let y2 = u2.sqrt();
    let e2 = y2.is_some();

    let u3 = x3.cube() + Fq::from(3u64);
    let y3 = u3.sqrt();
    // let e3 = y3.is_some();

    let x = Fq::conditional_select(&Fq::conditional_select(&x3, &x2, e2), &x1, e1);
    let mut y = y1.or_else(|| y2.or_else(|| y3)).unwrap();
    y = y * t_sign;

    G1::new_jacobian(x, y, Fq::ONE).unwrap()
}

pub(crate) fn hash_to_curve_evm<'a>(domain_prefix: &'a str) -> Box<dyn Fn(&[u8]) -> G1 + 'a> {
    Box::new(move |message| {
        let mut fs = [Fq::ZERO; 2];
        hash_to_field_evm(domain_prefix, message, &mut fs);

        let q0 = map_to_curve_evm(fs[0]);
        let q1 = map_to_curve_evm(fs[1]);

        let r = q0 + &q1;
        debug_assert!(bool::from(r.is_on_curve()));
        r
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2wrong::curves::group::Curve;

    #[test]
    fn test_hash() {
        let mut hasher = Keccak256::new();
        hasher.update(&[0u8]);
        let res = hasher.finalize().to_vec();
        println!("keccak hash rust {:?}", res);

        let mut res = [Fq::zero(); 2];
        hash_to_field_evm("evm compatible version", b"hello world", &mut res);
        println!("hash to field = {:?}", res);

        let hasher = hash_to_curve_evm("evm compatible version");
        let h = hasher(b"hello world");
        println!("hash to point = {:?}", h.to_affine());
        assert!(bool::from(h.is_on_curve()))
    }
}
