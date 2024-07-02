use crate::serialise::{
    le_bytes_to_hex, DkgGlobalPubParams as DkgGlobalPubParamsSerde,
    DkgShareKey as DkgShareKeySerde, Point,
};
use crate::{
    DKG_DIR, DKG_SECRETS_DIR, DKG_SHARES_DIR, MEMBERS_DIR, MEM_PUBLIC_KEYS_PATH, RANDOM_DIR,
};
use anyhow::Result;
use halo2wrong::curves::bn256::Fr as BnScalar;
use rand_core::RngCore;
use std::fs::{read_to_string, write};
use zkrand::dkg::{DkgConfig, PartialEval};
use zkrand::{
    combine_partial_evaluations, dkg_global_public_params, DkgGlobalPubParams, DkgMemberParams,
    DkgMemberPublicParams, DkgShareKey, MemberKey, PseudoRandom,
};

fn save_params(
    dkgs: &[DkgMemberParams],
    dkgs_pub: &[&DkgMemberPublicParams],
    gpp: &DkgGlobalPubParams,
) -> Result<()> {
    for (i, dkg) in dkgs.iter().enumerate() {
        let index = i + 1;
        let path = &format!("{DKG_SECRETS_DIR}/secret_{index}.json");
        let dkg_bytes: crate::serialise::DkgMemberParams = dkg.into();
        let serialized = serde_json::to_string(&dkg_bytes).unwrap();
        write(path, serialized.as_bytes())?;
    }

    {
        let path = &format!("{DKG_DIR}/dkgs_public.json");
        let dkgs_pub_bytes: Vec<crate::serialise::DkgMemberPublicParams> =
            dkgs_pub.iter().map(|&d| d.into()).collect();
        let serialized = serde_json::to_string(&dkgs_pub_bytes).unwrap();
        write(path, serialized.as_bytes())?;
    }

    {
        let path = &format!("{DKG_DIR}/gpp.json");
        let gpp_bytes: crate::serialise::DkgGlobalPubParams = gpp.into();
        let serialized = serde_json::to_string(&gpp_bytes).unwrap();
        write(path, serialized.as_bytes())?;

        let path = &format!("{DKG_DIR}/gpk.json");
        let gpk = gpp_bytes.g2a;
        let serialized = serde_json::to_string(&gpk).unwrap();
        write(path, serialized.as_bytes())?;

        let path = &format!("{DKG_DIR}/vks.json");
        let vks = gpp_bytes.verify_keys;
        let serialized = serde_json::to_string(&vks).unwrap();
        write(path, serialized.as_bytes())?;
    }

    Ok(())
}

fn save_shares(shares: &[DkgShareKey]) -> Result<()> {
    for share in shares.iter() {
        let index = share.index();
        let path = &format!("{DKG_SHARES_DIR}/share_{index}.json");
        let share_bytes: crate::serialise::DkgShareKey = share.into();
        let serialized = serde_json::to_string(&share_bytes).unwrap();
        write(path, serialized.as_bytes())?;
    }

    Ok(())
}

fn save_evals(sigmas: &[PartialEval], pseudo: &PseudoRandom) -> Result<()> {
    let bytes: Vec<crate::serialise::PartialEval> = sigmas.iter().map(|s| s.into()).collect();
    let seralised = serde_json::to_string(&bytes)?;
    let path = format!("{RANDOM_DIR}/evals.json");
    write(path, &seralised)?;

    let bytes: crate::serialise::PseudoRandom = pseudo.into();
    let serialised = serde_json::to_string(&bytes)?;
    let path = format!("{RANDOM_DIR}/pseudo.json");
    write(path, &serialised)?;
    Ok(())
}

fn save_instances(instances: &[Vec<BnScalar>]) -> Result<()> {
    let path = format!("{DKG_DIR}/all_instances.json");
    let mut instances_bytes = vec![];
    for instance in instances.iter() {
        let bytes: Vec<_> = instance
            .iter()
            .map(|x| le_bytes_to_hex(x.to_bytes()))
            .collect();
        instances_bytes.push(bytes);
    }
    // Write the bytes to the file
    let serialized = serde_json::to_string(&instances_bytes).unwrap();
    write(path, &serialized)?;
    Ok(())
}

pub fn mock_members(dkg_config: &DkgConfig, mut rng: impl RngCore) -> Result<()> {
    let mut mpks_bytes: Vec<Point> = vec![];
    let mut members_bytes: Vec<crate::serialise::MemberKey> = vec![];
    for _ in 0..dkg_config.number_of_members() {
        let member = MemberKey::random(&mut rng);
        let member_bytes = crate::serialise::MemberKey::from(member.clone());
        let mpk_bytes = member_bytes.pk.clone();

        mpks_bytes.push(mpk_bytes);
        members_bytes.push(member_bytes);
    }

    let serialized = serde_json::to_string(&mpks_bytes)?;
    write(MEM_PUBLIC_KEYS_PATH, &serialized)?;

    for (i, member) in members_bytes.iter().enumerate() {
        let path = format!("{MEMBERS_DIR}/member_{}.json", i + 1);
        let member_serialised = serde_json::to_string(member)?;
        write(path, &member_serialised)?;
    }

    Ok(())
}

pub fn mock_dkg(dkg_config: &DkgConfig, mut rng: impl RngCore) -> Result<()> {
    let mut members = vec![];
    let mut mpks = vec![];
    for i in 0..dkg_config.number_of_members() {
        let index = i + 1;
        let path = format!("{MEMBERS_DIR}/member_{index}.json");
        let bytes = read_to_string(path)?;
        let member_bytes: crate::serialise::MemberKey = serde_json::from_str(&bytes)?;
        let member: MemberKey = member_bytes.into();
        mpks.push(member.public_key());
        members.push(member);
    }

    // member index from 1..n
    let dkgs: Vec<_> = (0..dkg_config.number_of_members())
        .map(|_| DkgMemberParams::new(*dkg_config, mpks.clone(), &mut rng).unwrap())
        .collect();
    let dkgs_pub: Vec<_> = dkgs.iter().map(|dkg| dkg.member_public_params()).collect();

    let instances: Vec<_> = dkgs.iter().map(|dkg| dkg.instance()[0].clone()).collect();
    save_instances(&instances)?;

    // compute global public parameters
    let pp = dkg_global_public_params(&dkgs_pub);
    save_params(&dkgs, &dkgs_pub, &pp)?;

    // each member decrypt to obtain their own shares
    let mut shares = vec![];
    for i in 0..dkg_config.number_of_members() {
        let share = members[i]
            .dkg_share_key(&dkg_config, i + 1, &dkgs_pub)
            .unwrap();
        share.verify(&dkg_config, &pp.verify_keys).unwrap();

        shares.push(share);
    }

    save_shares(&shares)?;

    Ok(())
}

pub fn mock_random(dkg_config: &DkgConfig, input: &[u8], mut rng: impl RngCore) -> Result<()> {
    let mut shares = vec![];
    for i in 0..dkg_config.number_of_members() {
        let index = i + 1;
        let path = format!("{DKG_SHARES_DIR}/share_{index}.json");
        let bytes = read_to_string(path)?;
        let share_bytes: DkgShareKeySerde = serde_json::from_str(&bytes)?;
        let share: DkgShareKey = share_bytes.into();
        shares.push(share);
    }

    let path = format!("{DKG_DIR}/gpp.json");
    let bytes = read_to_string(path)?;
    let gpp_bytes: DkgGlobalPubParamsSerde = serde_json::from_str(&bytes)?;
    let gpp: DkgGlobalPubParams = gpp_bytes.into();

    let mut sigmas = vec![];
    for (i, share) in shares.iter().enumerate() {
        let sigma = share.evaluate(input, &mut rng);
        sigma
            .verify(dkg_config, input, &gpp.verify_keys[i])
            .unwrap();
        sigmas.push(sigma);
    }

    let v = combine_partial_evaluations(&dkg_config, &sigmas[0..dkg_config.threshold()]).unwrap();
    v.verify(input, &gpp.g2a).unwrap();

    save_evals(&sigmas, &v)?;

    Ok(())
}
