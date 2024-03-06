use halo2_ecc::halo2::halo2curves::group::Curve;
use halo2wrong::curves::bn256::{Fq, Fq2, Fr, G1Affine as BnG1, G2Affine as BnG2};
use halo2wrong::curves::grumpkin::G1Affine as GkG1;
use halo2wrong::curves::CurveAffine;
use hex::{decode, encode};
use serde::{Deserialize, Serialize};
use zkdvrf::{
    dkg::DkgConfig, dkg::PartialEval as PartialEvalCurve,
    dkg::PartialEvalProof as PartialEvalProofCurve, DkgGlobalPubParams as DkgGlobalPubParamsCurve,
    DkgMemberParams as DkgMemberParamsCurve, DkgMemberPublicParams as DkgMemberPublicParamsCurve,
    DkgShareKey as DkgShareKeyCurve, MemberKey as MemberKeyCurve,
    PseudoRandom as PseudoRandomCurve,
};

pub fn le_bytes_to_hex(bytes: [u8; 32]) -> String {
    // convert bytes in little endian to hex string with prefix "0x"
    let reverse: Vec<_> = bytes.into_iter().rev().collect();
    let hex_string = encode(&reverse).to_lowercase();
    format!("0x{}", hex_string)
}

pub fn hex_to_le_bytes(s: String) -> [u8; 32] {
    let trimmed = if s.starts_with("0x") { &s[2..] } else { &s };

    let bytes = decode(trimmed).expect("failed to decode hex to bytes");
    // Pad to 32 bytes with zeros
    let mut padded = [0u8; 32];
    let len = bytes.len();
    assert!(len <= 32);

    padded[32 - len..].copy_from_slice(&bytes);
    padded.reverse();
    padded
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Point {
    x: String,
    y: String,
}

impl From<GkG1> for Point {
    fn from(pk: GkG1) -> Self {
        let x = le_bytes_to_hex(pk.x.to_bytes());
        let y = le_bytes_to_hex(pk.y.to_bytes());
        Point { x, y }
    }
}

impl From<&GkG1> for Point {
    fn from(pk: &GkG1) -> Self {
        let x = le_bytes_to_hex(pk.x.to_bytes());
        let y = le_bytes_to_hex(pk.y.to_bytes());
        Point { x, y }
    }
}

impl From<BnG1> for Point {
    fn from(pk: BnG1) -> Self {
        let x = le_bytes_to_hex(pk.x.to_bytes());
        let y = le_bytes_to_hex(pk.y.to_bytes());
        Point { x, y }
    }
}

impl From<&BnG1> for Point {
    fn from(pk: &BnG1) -> Self {
        let x = le_bytes_to_hex(pk.x.to_bytes());
        let y = le_bytes_to_hex(pk.y.to_bytes());
        Point { x, y }
    }
}

impl Into<GkG1> for Point {
    fn into(self) -> GkG1 {
        let x_bytes = hex_to_le_bytes(self.x);
        let x = Fr::from_bytes(&x_bytes).expect("failed to deserialise x coord for Grumpkin point");
        let y_bytes = hex_to_le_bytes(self.y);
        let y = Fr::from_bytes(&y_bytes).expect("failed to deserialise y coord for Grumpkin point");
        GkG1::from_xy(x, y).expect("invalid Grumpkin point")
    }
}

impl Into<GkG1> for &Point {
    fn into(self) -> GkG1 {
        let x_bytes = hex_to_le_bytes(self.x.clone());
        let x = Fr::from_bytes(&x_bytes).expect("failed to deserialise x coord for Grumpkin point");
        let y_bytes = hex_to_le_bytes(self.y.clone());
        let y = Fr::from_bytes(&y_bytes).expect("failed to deserialise y coord for Grumpkin point");
        GkG1::from_xy(x, y).expect("invalid Grumpkin point")
    }
}

impl Into<BnG1> for Point {
    fn into(self) -> BnG1 {
        let x_bytes = hex_to_le_bytes(self.x);
        let x = Fq::from_bytes(&x_bytes).expect("failed to deserialise x coord for Bn256 G1 point");
        let y_bytes = hex_to_le_bytes(self.y);
        let y = Fq::from_bytes(&y_bytes).expect("failed to deserialise y coord for Bn256 G1 point");
        BnG1::from_xy(x, y).expect("invalid Bn256 G1 point")
    }
}

impl Into<BnG1> for &Point {
    fn into(self) -> BnG1 {
        let x_bytes = hex_to_le_bytes(self.x.clone());
        let x = Fq::from_bytes(&x_bytes).expect("failed to deserialise x coord for Bn256 G1 point");
        let y_bytes = hex_to_le_bytes(self.y.clone());
        let y = Fq::from_bytes(&y_bytes).expect("failed to deserialise y coord for Bn256 G1 point");
        BnG1::from_xy(x, y).expect("invalid Bn256 G1 point")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Point2 {
    x0: String,
    x1: String,
    y0: String,
    y1: String,
}

impl From<BnG2> for Point2 {
    fn from(pk: BnG2) -> Self {
        let x0 = le_bytes_to_hex(pk.x.c0.to_bytes());
        let x1 = le_bytes_to_hex(pk.x.c1.to_bytes());
        let y0 = le_bytes_to_hex(pk.y.c0.to_bytes());
        let y1 = le_bytes_to_hex(pk.y.c1.to_bytes());
        Point2 { x0, x1, y0, y1 }
    }
}

impl Into<BnG2> for Point2 {
    fn into(self) -> BnG2 {
        let x0_bytes = hex_to_le_bytes(self.x0);
        let x0 =
            Fq::from_bytes(&x0_bytes).expect("failed to deserialise x coord_0 for Bn256 G2 point");
        let x1_bytes = hex_to_le_bytes(self.x1);
        let x1 =
            Fq::from_bytes(&x1_bytes).expect("failed to deserialise x coord_1 for Bn256 G2 point");
        let y0_bytes = hex_to_le_bytes(self.y0);
        let y0 =
            Fq::from_bytes(&y0_bytes).expect("failed to deserialise y coord 0 for Bn256 G2 point");
        let y1_bytes = hex_to_le_bytes(self.y1);
        let y1 =
            Fq::from_bytes(&y1_bytes).expect("failed to deserialise y coord 1 for Bn256 G2 point");
        let x = Fq2::new(x0, x1);
        let y = Fq2::new(y0, y1);
        BnG2::from_xy(x, y).expect("invalid Bn256 G2 point")
    }
}

impl Into<BnG2> for &Point2 {
    fn into(self) -> BnG2 {
        let x0_bytes = hex_to_le_bytes(self.x0.clone());
        let x0 =
            Fq::from_bytes(&x0_bytes).expect("failed to deserialise x coord_0 for Bn256 G2 point");
        let x1_bytes = hex_to_le_bytes(self.x1.clone());
        let x1 =
            Fq::from_bytes(&x1_bytes).expect("failed to deserialise x coord_1 for Bn256 G2 point");
        let y0_bytes = hex_to_le_bytes(self.y0.clone());
        let y0 =
            Fq::from_bytes(&y0_bytes).expect("failed to deserialise y coord 0 for Bn256 G2 point");
        let y1_bytes = hex_to_le_bytes(self.y1.clone());
        let y1 =
            Fq::from_bytes(&y1_bytes).expect("failed to deserialise y coord 1 for Bn256 G2 point");
        let x = Fq2::new(x0, x1);
        let y = Fq2::new(y0, y1);
        BnG2::from_xy(x, y).expect("invalid Bn256 G2 point")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberKey {
    pub sk: String,
    pub pk: Point,
}

impl From<MemberKeyCurve> for MemberKey {
    fn from(mk: MemberKeyCurve) -> Self {
        let sk = le_bytes_to_hex(mk.secret_key().to_bytes());
        let pk: Point = mk.public_key().into();
        MemberKey { sk, pk }
    }
}

impl From<&MemberKeyCurve> for MemberKey {
    fn from(mk: &MemberKeyCurve) -> Self {
        let sk = le_bytes_to_hex(mk.secret_key().to_bytes());
        let pk: Point = mk.public_key().into();
        MemberKey { sk, pk }
    }
}

impl Into<MemberKeyCurve> for MemberKey {
    fn into(self) -> MemberKeyCurve {
        let sk_bytes = hex_to_le_bytes(self.sk);
        let sk = Fq::from_bytes(&sk_bytes).expect("failed to deserialise Grumpkin scalar");
        let pk: GkG1 = self.pk.into();
        let g = GkG1::generator();
        let p = (g * sk).to_affine();
        assert_eq!(pk, p);

        MemberKeyCurve::new(sk, pk)
    }
}

impl Into<MemberKeyCurve> for &MemberKey {
    fn into(self) -> MemberKeyCurve {
        let sk_bytes = hex_to_le_bytes(self.sk.clone());
        let sk = Fq::from_bytes(&sk_bytes).expect("failed to deserialise Grumpkin scalar");
        let pk: GkG1 = (&self.pk).into();
        let g = GkG1::generator();
        let p = (g * sk).to_affine();
        assert_eq!(pk, p);

        MemberKeyCurve::new(sk, pk)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgMemberPublicParams {
    // each member is indexed between 1...NUMBER_OF_MEMBERS
    public_shares: Vec<Point>,
    ciphers: Vec<String>,
    gr: Point,
    ga: Point,
    g2a: Point2,
}

impl From<DkgMemberPublicParamsCurve> for DkgMemberPublicParams {
    fn from(mp: DkgMemberPublicParamsCurve) -> Self {
        let public_shares: Vec<Point> = mp.public_shares.iter().map(|s| s.into()).collect();
        let ciphers: Vec<_> = mp
            .ciphers
            .iter()
            .map(|c| le_bytes_to_hex(c.to_bytes()))
            .collect();

        DkgMemberPublicParams {
            public_shares,
            ciphers,
            gr: mp.gr.into(),
            ga: mp.ga.into(),
            g2a: mp.g2a.into(),
        }
    }
}

impl From<&DkgMemberPublicParamsCurve> for DkgMemberPublicParams {
    fn from(mp: &DkgMemberPublicParamsCurve) -> Self {
        let public_shares: Vec<Point> = mp.public_shares.iter().map(|s| s.into()).collect();
        let ciphers: Vec<_> = mp
            .ciphers
            .iter()
            .map(|c| le_bytes_to_hex(c.to_bytes()))
            .collect();

        DkgMemberPublicParams {
            public_shares,
            ciphers,
            gr: mp.gr.into(),
            ga: mp.ga.into(),
            g2a: mp.g2a.into(),
        }
    }
}

impl Into<DkgMemberPublicParamsCurve> for DkgMemberPublicParams {
    fn into(self) -> DkgMemberPublicParamsCurve {
        let public_shares: Vec<BnG1> = self.public_shares.iter().map(|s| s.into()).collect();
        let ciphers: Vec<Fr> = self
            .ciphers
            .into_iter()
            .map(|c| {
                let c_bytes = hex_to_le_bytes(c);
                Fr::from_bytes(&c_bytes).expect("failed to deserialise Bn256 scalar")
            })
            .collect();

        DkgMemberPublicParamsCurve {
            public_shares,
            ciphers,
            gr: self.gr.into(),
            ga: self.ga.into(),
            g2a: self.g2a.into(),
        }
    }
}

impl Into<DkgMemberPublicParamsCurve> for &DkgMemberPublicParams {
    fn into(self) -> DkgMemberPublicParamsCurve {
        let public_shares: Vec<BnG1> = self.public_shares.iter().map(|s| s.into()).collect();
        let ciphers: Vec<Fr> = self
            .ciphers
            .iter()
            .cloned()
            .map(|c| {
                let c_bytes = hex_to_le_bytes(c);
                Fr::from_bytes(&c_bytes).expect("failed to deserialise Bn256 scalar")
            })
            .collect();

        DkgMemberPublicParamsCurve {
            public_shares,
            ciphers,
            gr: (&self.gr).into(),
            ga: (&self.ga).into(),
            g2a: (&self.g2a).into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgMemberParams {
    dkg_config: DkgConfig,
    coeffs: Vec<String>,
    shares: Vec<String>,
    r: String,
    public_keys: Vec<Point>,
    public_params: DkgMemberPublicParams,
}

impl From<DkgMemberParamsCurve> for DkgMemberParams {
    fn from(mp: DkgMemberParamsCurve) -> Self {
        let coeffs: Vec<_> = mp
            .coeffs
            .iter()
            .map(|c| le_bytes_to_hex(c.to_bytes()))
            .collect();
        let shares: Vec<_> = mp
            .shares
            .iter()
            .map(|s| le_bytes_to_hex(s.to_bytes()))
            .collect();
        let public_keys: Vec<Point> = mp.public_keys.iter().map(|p| p.into()).collect();
        let r = le_bytes_to_hex(mp.r.to_bytes());

        DkgMemberParams {
            dkg_config: mp.dkg_config,
            coeffs,
            shares,
            r,
            public_keys,
            public_params: mp.public_params.into(),
        }
    }
}

impl From<&DkgMemberParamsCurve> for DkgMemberParams {
    fn from(mp: &DkgMemberParamsCurve) -> Self {
        let coeffs: Vec<_> = mp
            .coeffs
            .iter()
            .map(|c| le_bytes_to_hex(c.to_bytes()))
            .collect();
        let shares: Vec<_> = mp
            .shares
            .iter()
            .map(|s| le_bytes_to_hex(s.to_bytes()))
            .collect();
        let public_keys: Vec<Point> = mp.public_keys.iter().map(|p| p.into()).collect();
        let r = le_bytes_to_hex(mp.r.to_bytes());

        DkgMemberParams {
            dkg_config: mp.dkg_config,
            coeffs,
            shares,
            r,
            public_keys,
            public_params: (&mp.public_params).into(),
        }
    }
}

impl Into<DkgMemberParamsCurve> for DkgMemberParams {
    fn into(self) -> DkgMemberParamsCurve {
        let coeffs: Vec<Fr> = self
            .coeffs
            .into_iter()
            .map(|c| {
                let c_bytes = hex_to_le_bytes(c);
                Fr::from_bytes(&c_bytes).expect("failed to deserialise Bn256 scalar")
            })
            .collect();

        let shares: Vec<Fr> = self
            .shares
            .into_iter()
            .map(|s| {
                let s_bytes = hex_to_le_bytes(s);
                Fr::from_bytes(&s_bytes).expect("failed to deserialise Bn256 scalar")
            })
            .collect();

        let r_bytes = hex_to_le_bytes(self.r);
        let r = Fr::from_bytes(&r_bytes).expect("failed to deserialise Bn256 scalar");

        let public_keys: Vec<GkG1> = self.public_keys.iter().map(|p| p.into()).collect();

        DkgMemberParamsCurve {
            dkg_config: self.dkg_config,
            coeffs,
            shares,
            r,
            public_keys,
            public_params: self.public_params.into(),
        }
    }
}

impl Into<DkgMemberParamsCurve> for &DkgMemberParams {
    fn into(self) -> DkgMemberParamsCurve {
        let coeffs: Vec<Fr> = self
            .coeffs
            .iter()
            .cloned()
            .map(|c| {
                let c_bytes = hex_to_le_bytes(c);
                Fr::from_bytes(&c_bytes).expect("failed to deserialise Bn256 scalar")
            })
            .collect();

        let shares: Vec<Fr> = self
            .shares
            .iter()
            .cloned()
            .map(|s| {
                let s_bytes = hex_to_le_bytes(s);
                Fr::from_bytes(&s_bytes).expect("failed to deserialise Bn256 scalar")
            })
            .collect();

        let r_bytes = hex_to_le_bytes(self.r.clone());
        let r = Fr::from_bytes(&r_bytes).expect("failed to deserialise Bn256 scalar");

        let public_keys: Vec<GkG1> = self.public_keys.iter().map(|p| p.into()).collect();

        DkgMemberParamsCurve {
            dkg_config: self.dkg_config,
            coeffs,
            shares,
            r,
            public_keys,
            public_params: (&self.public_params).into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgGlobalPubParams {
    pub ga: Point,
    pub g2a: Point2,
    pub verify_keys: Vec<Point>,
}

impl From<DkgGlobalPubParamsCurve> for DkgGlobalPubParams {
    fn from(gpp: DkgGlobalPubParamsCurve) -> Self {
        let verify_keys: Vec<Point> = gpp.verify_keys.iter().map(|vk| vk.into()).collect();

        DkgGlobalPubParams {
            ga: gpp.ga.into(),
            g2a: gpp.g2a.into(),
            verify_keys,
        }
    }
}

impl From<&DkgGlobalPubParamsCurve> for DkgGlobalPubParams {
    fn from(gpp: &DkgGlobalPubParamsCurve) -> Self {
        let verify_keys: Vec<Point> = gpp.verify_keys.iter().map(|vk| vk.into()).collect();

        DkgGlobalPubParams {
            ga: gpp.ga.into(),
            g2a: gpp.g2a.into(),
            verify_keys,
        }
    }
}

impl Into<DkgGlobalPubParamsCurve> for DkgGlobalPubParams {
    fn into(self) -> DkgGlobalPubParamsCurve {
        let verify_keys: Vec<BnG1> = self.verify_keys.iter().map(|vk| vk.into()).collect();

        DkgGlobalPubParamsCurve {
            ga: self.ga.into(),
            g2a: self.g2a.into(),
            verify_keys,
        }
    }
}

impl Into<DkgGlobalPubParamsCurve> for &DkgGlobalPubParams {
    fn into(self) -> DkgGlobalPubParamsCurve {
        let verify_keys: Vec<BnG1> = self.verify_keys.iter().map(|vk| vk.into()).collect();

        DkgGlobalPubParamsCurve {
            ga: (&self.ga).into(),
            g2a: (&self.g2a).into(),
            verify_keys,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgShareKey {
    index: usize,
    sk: String,
    vk: Point,
}

impl From<DkgShareKeyCurve> for DkgShareKey {
    fn from(dsk: DkgShareKeyCurve) -> Self {
        let sk = le_bytes_to_hex(dsk.secret_key().to_bytes());
        let vk: Point = dsk.verify_key().into();
        DkgShareKey {
            index: dsk.index(),
            sk,
            vk,
        }
    }
}

impl From<&DkgShareKeyCurve> for DkgShareKey {
    fn from(dsk: &DkgShareKeyCurve) -> Self {
        let sk = le_bytes_to_hex(dsk.secret_key().to_bytes());
        let vk: Point = dsk.verify_key().into();
        DkgShareKey {
            index: dsk.index(),
            sk,
            vk,
        }
    }
}

impl Into<DkgShareKeyCurve> for DkgShareKey {
    fn into(self) -> DkgShareKeyCurve {
        let sk_bytes = hex_to_le_bytes(self.sk);
        let sk = Fr::from_bytes(&sk_bytes).expect("failed to deserialise Bn256 scalar");
        let vk: BnG1 = self.vk.into();
        let g = BnG1::generator();
        let p = (g * sk).to_affine();
        assert_eq!(vk, p);

        DkgShareKeyCurve::new(self.index, sk, vk)
    }
}

impl Into<DkgShareKeyCurve> for &DkgShareKey {
    fn into(self) -> DkgShareKeyCurve {
        let sk_bytes = hex_to_le_bytes(self.sk.clone());
        let sk = Fr::from_bytes(&sk_bytes).expect("failed to deserialise Bn256 scalar");
        let vk: BnG1 = (&self.vk).into();
        let g = BnG1::generator();
        let p = (g * sk).to_affine();
        assert_eq!(vk, p);

        DkgShareKeyCurve::new(self.index, sk, vk)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialEvalProof {
    pub z: String,
    pub c: String,
}

impl From<PartialEvalProofCurve> for PartialEvalProof {
    fn from(proof: PartialEvalProofCurve) -> Self {
        let z = le_bytes_to_hex(proof.z.to_bytes());
        let c = le_bytes_to_hex(proof.c.to_bytes());

        PartialEvalProof { z, c }
    }
}

impl From<&PartialEvalProofCurve> for PartialEvalProof {
    fn from(proof: &PartialEvalProofCurve) -> Self {
        let z = le_bytes_to_hex(proof.z.to_bytes());
        let c = le_bytes_to_hex(proof.c.to_bytes());

        PartialEvalProof { z, c }
    }
}

impl Into<PartialEvalProofCurve> for PartialEvalProof {
    fn into(self) -> PartialEvalProofCurve {
        let z =
            Fr::from_bytes(&hex_to_le_bytes(self.z)).expect("failed to deserialise Bn256 scalar");
        let c =
            Fr::from_bytes(&hex_to_le_bytes(self.c)).expect("failed to deserialise Bn256 scalar");

        PartialEvalProofCurve { z, c }
    }
}

impl Into<PartialEvalProofCurve> for &PartialEvalProof {
    fn into(self) -> PartialEvalProofCurve {
        let z = Fr::from_bytes(&hex_to_le_bytes(self.z.clone()))
            .expect("failed to deserialise Bn256 scalar");
        let c = Fr::from_bytes(&hex_to_le_bytes(self.c.clone()))
            .expect("failed to deserialise Bn256 scalar");

        PartialEvalProofCurve { z, c }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialEval {
    pub index: usize,
    pub value: Point,
    pub proof: PartialEvalProof,
}

impl From<PartialEvalCurve> for PartialEval {
    fn from(sigma: PartialEvalCurve) -> Self {
        let value: Point = sigma.value.into();
        let proof = sigma.proof.into();
        PartialEval {
            index: sigma.index,
            value,
            proof,
        }
    }
}

impl From<&PartialEvalCurve> for PartialEval {
    fn from(sigma: &PartialEvalCurve) -> Self {
        let value: Point = sigma.value.into();
        let proof = (&sigma.proof).into();
        PartialEval {
            index: sigma.index,
            value,
            proof,
        }
    }
}

impl Into<PartialEvalCurve> for PartialEval {
    fn into(self) -> PartialEvalCurve {
        let value: BnG1 = self.value.into();
        let proof = self.proof.into();

        PartialEvalCurve {
            index: self.index,
            value,
            proof,
        }
    }
}

impl Into<PartialEvalCurve> for &PartialEval {
    fn into(self) -> PartialEvalCurve {
        let value: BnG1 = (&self.value).into();
        let proof = (&self.proof).into();
        PartialEvalCurve {
            index: self.index,
            value,
            proof,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudoRandom {
    proof: Point,
    value: Vec<u8>,
}

impl From<PseudoRandomCurve> for PseudoRandom {
    fn from(sigma: PseudoRandomCurve) -> Self {
        let proof: Point = sigma.proof.into();
        PseudoRandom {
            proof,
            value: sigma.value,
        }
    }
}

impl From<&PseudoRandomCurve> for PseudoRandom {
    fn from(sigma: &PseudoRandomCurve) -> Self {
        let proof: Point = sigma.proof.into();
        PseudoRandom {
            proof,
            value: sigma.value.clone(),
        }
    }
}

impl Into<PseudoRandomCurve> for PseudoRandom {
    fn into(self) -> PseudoRandomCurve {
        let proof: BnG1 = self.proof.into();

        PseudoRandomCurve {
            proof,
            value: self.value,
        }
    }
}

impl Into<PseudoRandomCurve> for &PseudoRandom {
    fn into(self) -> PseudoRandomCurve {
        let proof: BnG1 = (&self.proof).into();

        PseudoRandomCurve {
            proof,
            value: self.value.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2wrong::curves::ff::Field;
    use rand_core::OsRng;
    #[test]
    fn test_hex() {
        let mut rng = OsRng;
        let x = Fr::random(&mut rng);
        let bytes = x.to_bytes();
        let xs = le_bytes_to_hex(bytes);
        let z = hex_to_le_bytes(xs);
        assert_eq!(bytes, z);
    }
}
