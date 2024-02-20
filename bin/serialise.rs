use halo2_ecc::halo2::halo2curves::group::Curve;
use halo2wrong::curves::bn256::{Fq, Fq2, Fr, G1Affine as BnG1, G2Affine as BnG2};
use halo2wrong::curves::grumpkin::G1Affine as GkG1;
use halo2wrong::curves::CurveAffine;
use serde::{Deserialize, Serialize};
use zkdvrf::{
    dkg::DkgConfig, dkg::PartialEval as PartialEvalCurve,
    DkgGlobalPubParams as DkgGlobalPubParamsCurve, DkgMemberParams as DkgMemberParamsCurve,
    DkgMemberPublicParams as DkgMemberPublicParamsCurve, DkgShareKey as DkgShareKeyCurve,
    MemberKey as MemberKeyCurve, PseudoRandom as PseudoRandomCurve,
};

pub type Scalar = [u8; 32];
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Point {
    x: [u8; 32],
    y: [u8; 32],
}

impl From<GkG1> for Point {
    fn from(pk: GkG1) -> Self {
        let x = pk.x.to_bytes();
        let y = pk.y.to_bytes();
        Point { x, y }
    }
}

impl From<&GkG1> for Point {
    fn from(pk: &GkG1) -> Self {
        let x = pk.x.to_bytes();
        let y = pk.y.to_bytes();
        Point { x, y }
    }
}

impl From<BnG1> for Point {
    fn from(pk: BnG1) -> Self {
        let x = pk.x.to_bytes();
        let y = pk.y.to_bytes();
        Point { x, y }
    }
}

impl From<&BnG1> for Point {
    fn from(pk: &BnG1) -> Self {
        let x = pk.x.to_bytes();
        let y = pk.y.to_bytes();
        Point { x, y }
    }
}

impl Into<GkG1> for Point {
    fn into(self) -> GkG1 {
        let x = Fr::from_bytes(&self.x).expect("failed to deserialise x coord for Grumpkin point");
        let y = Fr::from_bytes(&self.y).expect("failed to deserialise y coord for Grumpkin point");
        GkG1::from_xy(x, y).expect("invalid Grumpkin point")
    }
}

impl Into<GkG1> for &Point {
    fn into(self) -> GkG1 {
        let x = Fr::from_bytes(&self.x).expect("failed to deserialise x coord for Grumpkin point");
        let y = Fr::from_bytes(&self.y).expect("failed to deserialise y coord for Grumpkin point");
        GkG1::from_xy(x, y).expect("invalid Grumpkin point")
    }
}

impl Into<BnG1> for Point {
    fn into(self) -> BnG1 {
        let x = Fq::from_bytes(&self.x).expect("failed to deserialise x coord for Bn256 point");
        let y = Fq::from_bytes(&self.y).expect("failed to deserialise y coord for Bn256 point");
        BnG1::from_xy(x, y).expect("invalid Bn256 point")
    }
}

impl Into<BnG1> for &Point {
    fn into(self) -> BnG1 {
        let x = Fq::from_bytes(&self.x).expect("failed to deserialise x coord for Bn256 point");
        let y = Fq::from_bytes(&self.y).expect("failed to deserialise y coord for Bn256 point");
        BnG1::from_xy(x, y).expect("invalid Bn256 point")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Point2 {
    x0: [u8; 32],
    x1: [u8; 32],
    y0: [u8; 32],
    y1: [u8; 32],
}

impl From<BnG2> for Point2 {
    fn from(pk: BnG2) -> Self {
        let x0 = pk.x.c0.to_bytes();
        let x1 = pk.x.c1.to_bytes();
        let y0 = pk.y.c0.to_bytes();
        let y1 = pk.y.c1.to_bytes();
        Point2 { x0, x1, y0, y1 }
    }
}

impl Into<BnG2> for Point2 {
    fn into(self) -> BnG2 {
        let x0 = Fq::from_bytes(&self.x0).expect("failed to deserialise x coord_0 for Bn256 point");
        let x1 = Fq::from_bytes(&self.x1).expect("failed to deserialise x coord_1 for Bn256 point");
        let y0 = Fq::from_bytes(&self.y0).expect("failed to deserialise y coord 0 for Bn256 point");
        let y1 = Fq::from_bytes(&self.y1).expect("failed to deserialise y coord 1 for Bn256 point");
        let x = Fq2::new(x0, x1);
        let y = Fq2::new(y0, y1);
        BnG2::from_xy(x, y).expect("invalid Bn256 G2 point")
    }
}

impl Into<BnG2> for &Point2 {
    fn into(self) -> BnG2 {
        let x0 = Fq::from_bytes(&self.x0).expect("failed to deserialise x coord_0 for Bn256 point");
        let x1 = Fq::from_bytes(&self.x1).expect("failed to deserialise x coord_1 for Bn256 point");
        let y0 = Fq::from_bytes(&self.y0).expect("failed to deserialise y coord 0 for Bn256 point");
        let y1 = Fq::from_bytes(&self.y1).expect("failed to deserialise y coord 1 for Bn256 point");
        let x = Fq2::new(x0, x1);
        let y = Fq2::new(y0, y1);
        BnG2::from_xy(x, y).expect("invalid Bn256 G2 point")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberKey {
    pub sk: Scalar,
    pub pk: Point,
}

impl From<MemberKeyCurve> for MemberKey {
    fn from(mk: MemberKeyCurve) -> Self {
        let sk = mk.secret_key().to_bytes();
        let pk: Point = mk.public_key().into();
        MemberKey { sk, pk }
    }
}

impl From<&MemberKeyCurve> for MemberKey {
    fn from(mk: &MemberKeyCurve) -> Self {
        let sk = mk.secret_key().to_bytes();
        let pk: Point = mk.public_key().into();
        MemberKey { sk, pk }
    }
}

impl Into<MemberKeyCurve> for MemberKey {
    fn into(self) -> MemberKeyCurve {
        let sk = Fq::from_bytes(&self.sk).expect("failed to deserialise Grumpkin scalar");
        let pk: GkG1 = self.pk.into();
        let g = GkG1::generator();
        let p = (g * sk).to_affine();
        assert_eq!(pk, p);

        MemberKeyCurve::new(sk, pk)
    }
}

impl Into<MemberKeyCurve> for &MemberKey {
    fn into(self) -> MemberKeyCurve {
        let sk = Fq::from_bytes(&self.sk).expect("failed to deserialise Grumpkin scalar");
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
    index: usize,
    public_shares: Vec<Point>,
    ciphers: Vec<Scalar>,
    gr: Point,
    ga: Point,
    g2a: Point2,
}

impl From<DkgMemberPublicParamsCurve> for DkgMemberPublicParams {
    fn from(mp: DkgMemberPublicParamsCurve) -> Self {
        let public_shares: Vec<Point> = mp.public_shares.iter().map(|s| s.into()).collect();
        let ciphers: Vec<Scalar> = mp.ciphers.iter().map(|c| c.to_bytes()).collect();

        DkgMemberPublicParams {
            index: mp.index,
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
        let ciphers: Vec<Scalar> = mp.ciphers.iter().map(|c| c.to_bytes()).collect();

        DkgMemberPublicParams {
            index: mp.index,
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
            .iter()
            .map(|c| Fr::from_bytes(c).expect("failed to deserialise Bn256 scalar"))
            .collect();

        DkgMemberPublicParamsCurve {
            index: self.index,
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
            .map(|c| Fr::from_bytes(c).expect("failed to deserialise Bn256 scalar"))
            .collect();

        DkgMemberPublicParamsCurve {
            index: self.index,
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
    coeffs: Vec<Scalar>,
    shares: Vec<Scalar>,
    r: Scalar,
    public_keys: Vec<Point>,
    public_params: DkgMemberPublicParams,
}

impl From<DkgMemberParamsCurve> for DkgMemberParams {
    fn from(mp: DkgMemberParamsCurve) -> Self {
        let coeffs: Vec<Scalar> = mp.coeffs.iter().map(|c| c.to_bytes()).collect();
        let shares: Vec<Scalar> = mp.shares.iter().map(|s| s.to_bytes()).collect();
        let public_keys: Vec<Point> = mp.public_keys.iter().map(|p| p.into()).collect();

        DkgMemberParams {
            dkg_config: mp.dkg_config,
            coeffs,
            shares,
            r: mp.r.to_bytes(),
            public_keys,
            public_params: mp.public_params.into(),
        }
    }
}

impl From<&DkgMemberParamsCurve> for DkgMemberParams {
    fn from(mp: &DkgMemberParamsCurve) -> Self {
        let coeffs: Vec<Scalar> = mp.coeffs.iter().map(|c| c.to_bytes()).collect();
        let shares: Vec<Scalar> = mp.shares.iter().map(|s| s.to_bytes()).collect();
        let public_keys: Vec<Point> = mp.public_keys.iter().map(|p| p.into()).collect();

        DkgMemberParams {
            dkg_config: mp.dkg_config,
            coeffs,
            shares,
            r: mp.r.to_bytes(),
            public_keys,
            public_params: (&mp.public_params).into(),
        }
    }
}

impl Into<DkgMemberParamsCurve> for DkgMemberParams {
    fn into(self) -> DkgMemberParamsCurve {
        let coeffs: Vec<Fr> = self
            .coeffs
            .iter()
            .map(|c| Fr::from_bytes(c).expect("failed to deserialise Bn256 scalar"))
            .collect();

        let shares: Vec<Fr> = self
            .shares
            .iter()
            .map(|s| Fr::from_bytes(s).expect("failed to deserialise Bn256 scalar"))
            .collect();

        let r = Fr::from_bytes(&self.r).expect("failed to deserialise Bn256 scalar");

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
            .map(|c| Fr::from_bytes(c).expect("failed to deserialise Bn256 scalar"))
            .collect();

        let shares: Vec<Fr> = self
            .shares
            .iter()
            .map(|s| Fr::from_bytes(s).expect("failed to deserialise Bn256 scalar"))
            .collect();

        let r = Fr::from_bytes(&self.r).expect("failed to deserialise Bn256 scalar");

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
    sk: Scalar,
    vk: Point,
}

impl From<DkgShareKeyCurve> for DkgShareKey {
    fn from(dsk: DkgShareKeyCurve) -> Self {
        let sk = dsk.secret_key().to_bytes();
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
        let sk = dsk.secret_key().to_bytes();
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
        let sk = Fr::from_bytes(&self.sk).expect("failed to deserialise Bn256 scalar");
        let vk: BnG1 = self.vk.into();
        let g = BnG1::generator();
        let p = (g * sk).to_affine();
        assert_eq!(vk, p);

        DkgShareKeyCurve::new(self.index, sk, vk)
    }
}

impl Into<DkgShareKeyCurve> for &DkgShareKey {
    fn into(self) -> DkgShareKeyCurve {
        let sk = Fr::from_bytes(&self.sk).expect("failed to deserialise Bn256 scalar");
        let vk: BnG1 = (&self.vk).into();
        let g = BnG1::generator();
        let p = (g * sk).to_affine();
        assert_eq!(vk, p);

        DkgShareKeyCurve::new(self.index, sk, vk)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialEval {
    pub index: usize,
    pub value: Point,
    pub proof: (Scalar, Scalar),
}

impl From<PartialEvalCurve> for PartialEval {
    fn from(sigma: PartialEvalCurve) -> Self {
        let value: Point = sigma.value.into();
        let proof: (Scalar, Scalar) = (sigma.proof.0.into(), sigma.proof.1.into());
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
        let proof: (Scalar, Scalar) = (sigma.proof.0.into(), sigma.proof.1.into());
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
        let proof = (
            Fr::from_bytes(&self.proof.0).expect("failed to deserialise Bn256 scalar"),
            Fr::from_bytes(&self.proof.1).expect("failed to deserialise Bn256 scalar"),
        );

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
        let proof = (
            Fr::from_bytes(&self.proof.0).expect("failed to deserialise Bn256 scalar"),
            Fr::from_bytes(&self.proof.1).expect("failed to deserialise Bn256 scalar"),
        );

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
