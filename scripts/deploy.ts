import hre, {artifacts, ethers} from "hardhat";
import {Contract, ContractFactory, providers, utils, Wallet} from "ethers";

async function main() {
  const netprovider = new providers.JsonRpcProvider(process.env.RPC_URL)
  const accPrivateKey = process.env.PRIVATE_KEY ?? ''
  const deployerWallet = new Wallet(accPrivateKey, netprovider)
  const minDeposit = process.env.MIN_DEPOSIT ?? '0'
  const deployNoHelpers = process.env.DEPLOY_NO_HELPERS === 'true'

  let halo2VerifierAddress
  let globalPublicParamsAddress
  let pseudoRandAddress

  if (deployNoHelpers) {
    halo2VerifierAddress = process.env.HALO2V 
    globalPublicParamsAddress = process.env.GPP
    pseudoRandAddress = process.env.PSRAND
  } else {
    const Halo2Verifier = await ethers.getContractFactory('contracts/Halo2Verifier-3-5-g2.sol:Halo2Verifier')
    const halo2Verifier = await Halo2Verifier.connect(deployerWallet).deploy()
    await halo2Verifier.deployed()
  
    console.log("Halo2Verifier deployed at", halo2Verifier.address)
  
    const GlobalPublicParams = await ethers.getContractFactory('GlobalPublicParams')
    const globalPublicParams = await GlobalPublicParams.connect(deployerWallet).deploy()
    await globalPublicParams.deployed()
  
    console.log("GlobalPublicParams deployed at", globalPublicParams.address)
  
    const PseudoRand = await ethers.getContractFactory('PseudoRand')
    const pseudoRand = await PseudoRand.connect(deployerWallet).deploy()
    await pseudoRand.deployed()
  
    console.log("PseudoRand deployed at", pseudoRand.address)

    halo2VerifierAddress = halo2Verifier.address
    globalPublicParamsAddress = globalPublicParams.address
    pseudoRandAddress = pseudoRand.address
  }

  const Zkdvrf = await ethers.getContractFactory('zkdvrf')
  const zkdvrf = await Zkdvrf.connect(deployerWallet).deploy(halo2VerifierAddress, globalPublicParamsAddress, pseudoRandAddress, minDeposit)
  await zkdvrf.deployed()

  console.log("Zkdvrf deployed at", zkdvrf.address)
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
