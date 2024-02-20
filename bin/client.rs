use anyhow::{anyhow, Result};
use ark_std::{end_timer, start_timer};
use clap::{Args, Parser, Subcommand};
use config::Config;
use const_format::formatcp;
use halo2_ecc::halo2::halo2curves::bn256::Fr as BnScalar;
use halo2_solidity_verifier::BatchOpenScheme::Bdfg21;
use halo2_solidity_verifier::SolidityGenerator;
use halo2wrong::curves::grumpkin::G1Affine as GkG1;
use halo2wrong::halo2::poly::commitment::ParamsProver;
use log::info;
use pretty_env_logger;
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, read, read_to_string, write};
use toml::to_string_pretty;

use crate::mock::{mock_dkg, mock_members, mock_random};
use crate::proof::{create_proof_checked, verify_single};
use crate::serialise::{
    DkgGlobalPubParams as DkgGlobalPubParamsSerde, DkgMemberParams as DkgMemberParamsSerde,
    DkgMemberPublicParams as DkgMemberPublicParamsSerde, DkgShareKey as DkgShareKeySerde,
    MemberKey as MemberKeySerde, PartialEval as PartialEvalSerde, Point,
    PseudoRandom as PseudoRandomSerde,
};

use zkdvrf::dkg::{DkgConfig, PartialEval};
use zkdvrf::{
    combine_partial_evaluations, dkg_global_public_params, load_or_create_params,
    load_or_create_pk, load_or_create_vk, DkgGlobalPubParams, DkgMemberParams,
    DkgMemberPublicParams, DkgShareKey, MemberKey, PseudoRandom,
};

mod mock;
mod proof;
mod serialise;

const KZG_PARAMS_DIR: &str = "./kzg_params";
const CONTRACT_DIR: &str = "./contracts";
const DATA_DIR: &str = "./data";
const CONFIG_PATH: &str = formatcp!("{}/config.toml", DATA_DIR);
const MEM_PUBLIC_KEYS_PATH: &str = formatcp!("{}/mpks.json", DATA_DIR);
const MEMBERS_DIR: &str = formatcp!("{}/members", DATA_DIR);
const DKG_DIR: &str = formatcp!("{}/dkg", DATA_DIR);
const DKG_SECRETS_DIR: &str = formatcp!("{}/secrets", DKG_DIR);
const DKG_PROOFS_DIR: &str = formatcp!("{}/proofs", DKG_DIR);
const DKG_SHARES_DIR: &str = formatcp!("{}/shares", DKG_DIR);
const RANDOM_DIR: &str = "./data/random";

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Set values (threshold, number of members, degree) in config
    Config {
        threshold: u32,
        number_of_members: u32,
        degree: u32,
    },
    /// Mock n members and dkg parameters
    Mock(MockArgs),
    /// Generate kzg parameters, proving key and verifying key for SNARKs and verifier contract
    Setup,
    /// Generate member secret/public key pair
    Keygen,
    /// Dkg commands
    Dkg(DkgArgs),
    /// Random commands
    Rand(RandArgs),
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
struct DkgArgs {
    #[command(subcommand)]
    command: DkgCommands,
}

#[derive(Debug, Subcommand)]
enum DkgCommands {
    /// Create dkg parameters and a snark proof for member i
    Prove { index: usize },
    /// Verify the snark proof for dkg public parameters for member i
    Verify { index: usize },
    /// Derive the global public parameters and (if index is given) the secret share for member i.
    /// Read the member's secret key from file zkdvrf/data/members/<file>.json;
    Derive {
        index: Option<usize>,
        #[arg(short, default_value = "member")]
        file: Option<String>,
    },
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
struct RandArgs {
    #[command(subcommand)]
    command: RandCommands,
}

#[derive(Debug, Subcommand)]
enum RandCommands {
    /// Create partial evaluation on input string for member i
    Eval {
        index: usize,
        input: String,
    },
    /// Verify the partial evaluation on input string for member i
    Verify {
        index: usize,
        input: String,
    },
    /// Combine partial evaluations into the final pseudorandom.
    /// Default verify = true. If verify = false, it skips the verification of partial evaluations.
    Combine {
        input: String,
        #[arg(short, long, default_value_t = true)]
        verify: bool,
    },
    VerifyFinal {
        input: String,
    },
}

#[derive(Debug, Args)]
struct MockArgs {
    /// Mock members by creating member secret/public keys
    #[arg(short, long = "mem", default_value_t = false)]
    members: bool,
    /// Mock dkg protocol for all the members; need to mock members first
    #[arg(short, long, default_value_t = false)]
    dkg: bool,
    /// Mock generation of partial evaluations and final pseudorandom value on an input; need to mock members and dkg first
    #[arg(short, long = "rand", value_name = "input")]
    random: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ParamsConfig {
    threshold: u32,
    number_of_members: u32,
    degree: u32,
}

impl ParamsConfig {
    pub fn dkg_config(&self) -> Result<DkgConfig> {
        let config = DkgConfig::new(self.threshold as usize, self.number_of_members as usize);

        match config {
            Ok(c) => Ok(c),
            Err(_) => Err(anyhow!("invalid thrshold and number of members for dkg")),
        }
    }
}

fn update_config(threshold: u32, number_of_members: u32, degree: u32) -> Result<()> {
    let min_threshold = (number_of_members + 2) / 2;
    if threshold < min_threshold || threshold > number_of_members {
        return Err(anyhow!("invalid threshold"));
    }

    let params = ParamsConfig {
        threshold,
        number_of_members,
        degree,
    };
    let toml_str = to_string_pretty(&params)?;

    // Write the TOML string to a file
    write(CONFIG_PATH, toml_str)?;
    info!("config saved in {CONFIG_PATH}");

    Ok(())
}

fn save_share(share: &DkgShareKey) -> Result<()> {
    let index = share.index();
    let path = &format!("{DKG_SHARES_DIR}/share_{index}.json");
    let share_bytes: DkgShareKeySerde = share.into();
    let serialized = serde_json::to_string(&share_bytes).unwrap();
    write(path, serialized.as_bytes())?;
    info!("dkg secret share for member {index} saved in {path}");
    Ok(())
}

fn save_gpp(gpp: &DkgGlobalPubParams) -> Result<()> {
    let path = &format!("{DKG_DIR}/gpp.json");
    let gpp_bytes: DkgGlobalPubParamsSerde = gpp.into();
    let serialized = serde_json::to_string(&gpp_bytes).unwrap();
    write(path, serialized.as_bytes())?;
    info!("global public parameters saved in {path}");
    Ok(())
}

fn save_solidity(name: impl AsRef<str>, solidity: &str) -> Result<()> {
    let path = &format!("{CONTRACT_DIR}/{}", name.as_ref());
    write(path, solidity.as_bytes())?;
    info!("solidity contract {} saved in {path}", name.as_ref());
    Ok(())
}

fn save_proof(proof: &[u8], instance: &[BnScalar], index: usize) -> Result<()> {
    let path = &format!("{DKG_PROOFS_DIR}/proof_{index}.dat");
    write(path, proof).unwrap();

    let path = &format!("{DKG_PROOFS_DIR}/instance_{index}.json");
    let instance_bytes: Vec<_> = instance.iter().map(|x| x.to_bytes()).collect();
    let serialized = serde_json::to_string(&instance_bytes).unwrap();
    write(path, serialized.as_bytes())?;
    info!("snark proof and instance for member {index} saved in {path}");
    Ok(())
}

fn setup(params: &ParamsConfig) -> Result<()> {
    let start = start_timer!(|| format!("kzg load or setup params with degree {}", params.degree));
    let general_params = load_or_create_params(KZG_PARAMS_DIR, params.degree as usize).unwrap();
    end_timer!(start);

    let dkg_config = params.dkg_config()?;

    let start = start_timer!(|| format!(
        "kzg load or setup proving keys with degree {}",
        params.degree
    ));
    let pk = load_or_create_pk(
        dkg_config,
        KZG_PARAMS_DIR,
        &general_params,
        params.degree as usize,
    )
    .unwrap();
    let vk = pk.get_vk();
    end_timer!(start);

    let num_instances = dkg_config.circuit_instance_size();
    let start = start_timer!(|| format!("create solidity contracts"));
    let generator = SolidityGenerator::new(&general_params, vk, Bdfg21, num_instances);
    let verifier_solidity = generator.render().unwrap();

    let contract_name = if cfg!(feature = "g2chip") {
        format!(
            "Halo2Verifier-{}-{}-g2.sol",
            dkg_config.threshold(),
            dkg_config.number_of_members()
        )
    } else {
        format!(
            "Halo2Verifier-{}-{}.sol",
            dkg_config.threshold(),
            dkg_config.number_of_members()
        )
    };

    save_solidity(contract_name, &verifier_solidity)?;
    end_timer!(start);
    Ok(())
}

fn load_config() -> ParamsConfig {
    let settings = Config::builder()
        .add_source(config::File::with_name(CONFIG_PATH))
        .build()
        .unwrap();
    let params: ParamsConfig = settings.try_deserialize().unwrap();
    // todo: implement StdError for zkdvrf errors
    // todo: automatically generate or check degree
    params
}

fn main() -> Result<()> {
    pretty_env_logger::init();
    //    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let mut rng = OsRng;

    create_dir_all(MEMBERS_DIR)?;
    create_dir_all(DKG_SECRETS_DIR)?;
    create_dir_all(DKG_PROOFS_DIR)?;
    create_dir_all(DKG_SHARES_DIR)?;
    create_dir_all(CONTRACT_DIR)?;
    create_dir_all(RANDOM_DIR)?;

    let params = load_config();
    let dkg_config = params.dkg_config()?;

    let cli = Cli::parse();
    match cli.command {
        Commands::Config {
            threshold,
            number_of_members,
            degree,
        } => {
            update_config(threshold, number_of_members, degree)?;
        }
        Commands::Mock(mock) => {
            if mock.members {
                mock_members(&dkg_config, &mut rng)?;
                info!("{} members generated", dkg_config.number_of_members());
            }

            if mock.dkg {
                mock_dkg(&dkg_config, &mut rng)?;
                info!(
                    "threshold {}-out-of-{} dkg generated",
                    dkg_config.threshold(),
                    dkg_config.number_of_members()
                );
            }

            if let Some(input) = mock.random {
                mock_random(&dkg_config, input.as_bytes(), &mut rng)?;
                info!(
                    "created partial evaluations and pseudorandom on input \"{}\"",
                    input
                );
            }
        }
        Commands::Setup => {
            setup(&params)?;
        }
        Commands::Keygen => {
            let member = MemberKey::random(&mut rng);
            let mpk = member.public_key();
            let member_bytes: MemberKeySerde = member.into();

            let path = &format!("{MEMBERS_DIR}/member.json");
            let member_seralised = serde_json::to_string(&member_bytes)?;
            write(path, &member_seralised)?;
            info!("member secret key and public key generated and saved in {path}");

            let mpk_bytes: Point = mpk.into();
            let mpk_serialised = serde_json::to_string(&mpk_bytes)?;
            info!("member public key is {}", mpk_serialised);
            // TODO: network transmission for public key
        }
        Commands::Dkg(dkg) => {
            match dkg.command {
                DkgCommands::Prove { index } => {
                    if index < 1 || index > dkg_config.number_of_members() {
                        return Err(anyhow!("Invalid member index"));
                    }
                    // read all member public keys
                    let bytes = read_to_string(MEM_PUBLIC_KEYS_PATH)?;
                    let mpks_bytes: Vec<Point> = serde_json::from_str(&bytes)?;
                    let mpks: Vec<GkG1> = mpks_bytes.into_iter().map(|pk| pk.into()).collect();

                    let dkg = DkgMemberParams::new(dkg_config, index + 1, mpks, &mut rng).unwrap();
                    {
                        // save dkg secrets for member i
                        let path = &format!("{DKG_SECRETS_DIR}/secret_{index}.json");
                        let dkg_bytes: DkgMemberParamsSerde = (&dkg).into();
                        let serialized = serde_json::to_string(&dkg_bytes).unwrap();
                        write(path, serialized.as_bytes())?;
                        info!("dkg secrets for member {index} generated and saved in {path}");
                    }

                    let circuit = dkg.circuit(&mut rng);
                    let instance = dkg.instance();

                    let start = start_timer!(|| format!(
                        "kzg load or setup params with degree {}",
                        params.degree
                    ));
                    let params_dir = "./kzg_params";
                    let general_params =
                        load_or_create_params(params_dir, params.degree as usize).unwrap();
                    end_timer!(start);

                    let start = start_timer!(|| format!(
                        "kzg load or setup proving keys with degree {}",
                        params.degree
                    ));
                    let pk = load_or_create_pk(
                        dkg_config,
                        params_dir,
                        &general_params,
                        params.degree as usize,
                    )
                    .unwrap();
                    end_timer!(start);

                    let start = start_timer!(|| format!("create and verify proof"));
                    let proof =
                        create_proof_checked(&general_params, &pk, circuit, &instance[0], &mut rng);
                    end_timer!(start);
                    info!("size of proof {:?}", proof.len());

                    // todo: network transmission for (proof, instance[0])
                    save_proof(&proof, &instance[0], index)?;
                }
                DkgCommands::Verify { index } => {
                    if index < 1 || index > dkg_config.number_of_members() {
                        return Err(anyhow!("Invalid member index"));
                    }

                    let proof_path = &format!("{DKG_PROOFS_DIR}/proof_{index}.dat");
                    let proof = read(proof_path).unwrap();

                    // read instance
                    let instance_path = format!("{DKG_PROOFS_DIR}/instance_{index}.json");
                    let bytes = read_to_string(instance_path)?;
                    let instance_bytes: Vec<[u8; 32]> = serde_json::from_str(&bytes)?;
                    let instance: Vec<BnScalar> = instance_bytes
                        .iter()
                        .map(|e| {
                            BnScalar::from_bytes(e).expect("failed to deserialise Bn256 scalar")
                        })
                        .collect();

                    let start = start_timer!(|| format!(
                        "kzg load or setup params with degree {}",
                        params.degree
                    ));
                    let params_dir = "./kzg_params";
                    let general_params =
                        load_or_create_params(params_dir, params.degree as usize).unwrap();
                    end_timer!(start);

                    let start = start_timer!(|| format!(
                        "kzg load or setup verifying keys with degree {}",
                        params.degree
                    ));
                    let vk = load_or_create_vk(
                        dkg_config,
                        params_dir,
                        &general_params,
                        params.degree as usize,
                    )
                    .unwrap();
                    end_timer!(start);

                    verify_single(general_params.verifier_params(), &vk, &proof, &instance);
                }
                DkgCommands::Derive { index, file } => {
                    let path = &format!("{DKG_DIR}/dkgs_public.json");
                    let bytes = read_to_string(path)?;
                    let dkgs_pub_bytes: Vec<DkgMemberPublicParamsSerde> =
                        serde_json::from_str(&bytes)?;
                    let dkgs_pub: Vec<DkgMemberPublicParams> =
                        dkgs_pub_bytes.into_iter().map(|d| d.into()).collect();
                    let dkgs_pub_ref: Vec<_> = dkgs_pub.iter().map(|d| d).collect();

                    let gpp = dkg_global_public_params(&dkgs_pub_ref);
                    save_gpp(&gpp)?;

                    if let Some(index) = index {
                        if index < 1 || index > dkg_config.number_of_members() {
                            return Err(anyhow!("Invalid member index"));
                        }

                        let path = file
                            .map(|f| format!("{MEMBERS_DIR}/{f}.json"))
                            .ok_or_else(|| anyhow!("file path not available"))?;
                        let bytes = read_to_string(path)?;
                        let member_bytes: MemberKeySerde = serde_json::from_str(&bytes)?;
                        let member: MemberKey = member_bytes.into();

                        let share = member
                            .dkg_share_key(&dkg_config, index, &dkgs_pub_ref)
                            .unwrap();
                        share.verify(&dkg_config, &gpp.verify_keys).unwrap();

                        save_share(&share)?;
                    }
                }
            }
        }
        Commands::Rand(rand) => {
            match rand.command {
                RandCommands::Eval { index, input } => {
                    if index < 1 || index > dkg_config.number_of_members() {
                        return Err(anyhow!("Invalid member index"));
                    }

                    let path = &format!("{DKG_SHARES_DIR}/share_{index}.json");
                    let bytes = read_to_string(path)?;
                    let share_bytes: DkgShareKeySerde = serde_json::from_str(&bytes)?;
                    let share: DkgShareKey = share_bytes.into();
                    let sigma = share.evaluate(input.as_bytes(), &mut rng);
                    let sigma_bytes: PartialEvalSerde = sigma.into();
                    let serialised = serde_json::to_string(&sigma_bytes)?;
                    let path = &format!("{RANDOM_DIR}/eval_{index}.json");
                    write(path, serialised.as_bytes())?;
                    info!("partial eval for member {index} on input \"{input}\" generated and saved in {path}");
                }
                RandCommands::Verify { index, input } => {
                    if index < 1 || index > dkg_config.number_of_members() {
                        return Err(anyhow!("Invalid member index"));
                    }

                    let path = &format!("{RANDOM_DIR}/eval_{index}.json");
                    let bytes = read_to_string(path)?;
                    let sigma_bytes: PartialEvalSerde = serde_json::from_str(&bytes)?;
                    let sigma: PartialEval = sigma_bytes.into();

                    let path = &format!("{DKG_DIR}/gpp.json");
                    let bytes = read_to_string(path)?;
                    let gpp_bytes: DkgGlobalPubParamsSerde = serde_json::from_str(&bytes)?;
                    let gpp: DkgGlobalPubParams = gpp_bytes.into();

                    sigma
                        .verify(&dkg_config, input.as_bytes(), &gpp.verify_keys[index - 1])
                        .unwrap();
                    info!("partial eval for member {index} on input \"{input}\" verified successfully");
                }
                RandCommands::Combine { input, verify } => {
                    let path = format!("{RANDOM_DIR}/evals.json");
                    let bytes = read_to_string(path)?;
                    let evals_bytes: Vec<PartialEvalSerde> = serde_json::from_str(&bytes)?;
                    let evals: Vec<PartialEval> =
                        evals_bytes.into_iter().map(|e| e.into()).collect();

                    // read dkg global public parameters
                    let path = format!("{DKG_DIR}/gpp.json");
                    let bytes = read_to_string(path)?;
                    let gpp_bytes: DkgGlobalPubParamsSerde = serde_json::from_str(&bytes)?;
                    let gpp: DkgGlobalPubParams = gpp_bytes.into();

                    let mut verified = vec![];
                    if verify {
                        for e in evals.into_iter() {
                            if e.index < 1 || e.index > dkg_config.number_of_members() {
                                return Err(anyhow!("Invalid member index {:?}", e.index));
                            }

                            let i = e.index - 1;
                            if e.verify(&dkg_config, input.as_bytes(), &gpp.verify_keys[i])
                                .is_ok()
                            {
                                verified.push(e);
                            }
                        }
                    } else {
                        // skip verification on partial evaluations
                        verified = evals;
                    }

                    if verified.len() < dkg_config.threshold() {
                        return Err(anyhow!("not enough valid partial evaluations"));
                    }

                    // todo: improve error handling
                    let pseudo = combine_partial_evaluations(
                        &dkg_config,
                        &verified[0..dkg_config.threshold()],
                    )
                    .unwrap();

                    pseudo.verify(input.as_bytes(), &gpp.g2a).unwrap();

                    let pseudo_bytes: PseudoRandomSerde = pseudo.into();
                    let serialized = serde_json::to_string(&pseudo_bytes).unwrap();
                    let path = &format!("{RANDOM_DIR}/pseudo.json");
                    write(path, serialized.as_bytes())?;
                    info!(
                        "final pseudorandom on input \"{}\" generated and saved at {}",
                        input, path
                    );
                    // todo: network transmission for pseudo random
                }
                RandCommands::VerifyFinal { input } => {
                    let path = &format!("{RANDOM_DIR}/pseudo.json");
                    let bytes = read_to_string(path)?;
                    let pseudo_bytes: PseudoRandomSerde = serde_json::from_str(&bytes)?;
                    let pseudo: PseudoRandom = pseudo_bytes.into();

                    // read dkg global public parameters
                    let path = format!("{DKG_DIR}/gpp.json");
                    let bytes = read_to_string(path)?;
                    let gpp_bytes: DkgGlobalPubParamsSerde = serde_json::from_str(&bytes)?;
                    let gpp: DkgGlobalPubParams = gpp_bytes.into();

                    pseudo.verify(input.as_bytes(), &gpp.g2a).unwrap();
                    info!("final pseudorandom on input \"{input}\" verified successfully");
                }
            }
        }
    }

    Ok(())
}
