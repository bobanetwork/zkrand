import hre, {artifacts, ethers} from "hardhat";
import {Contract, ContractFactory, providers, utils, Wallet} from "ethers";

async function main() {
    const netprovider = new providers.JsonRpcProvider(process.env.L2_NODE_WEB3_URL)
    const accPrivateKey = process.env.DEPLOYER_PRIVATE_KEY ?? ''
    const adminAddress = process.env.ADMIN_ADDRESS ?? ''
    const deployerWallet = new Wallet(accPrivateKey, netprovider)
    const threshold = process.env.THRESHOLD
    const numberOfMembers = process.env.NUMBER_OF_MEMBERS
    const degree = process.env.DEGREE
    const minDeposit = process.env.MIN_DEPOSIT ?? '0'
    const deployNoHelpers = process.env.DEPLOY_NO_HELPERS === 'true'

    let halo2VerifierAddress
    let halo2VerifyingKeyAddress
    let globalPublicParamsAddress
    let pseudoRandAddress

    if (deployNoHelpers) {
        halo2VerifierAddress = process.env.HALO2V
        halo2VerifyingKeyAddress = process.env.HALO2VK
        globalPublicParamsAddress = process.env.GPP
        pseudoRandAddress = process.env.PSRAND
    } else {
        const Halo2VerifyingKey = await ethers.getContractFactory(`contracts/Halo2VerifyingKey-${threshold}-${numberOfMembers}-${degree}-g2.sol:Halo2VerifyingKey`)
        const halo2VerifyingKey = await Halo2VerifyingKey.connect(deployerWallet).deploy()
        await halo2VerifyingKey.deployed()

        console.log("Halo2VerifyingKey deployed at", halo2VerifyingKey.address)

        const Halo2Verifier = await ethers.getContractFactory('contracts/Halo2Verifier.sol:Halo2Verifier')
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

        halo2VerifyingKeyAddress = halo2VerifyingKey.address
        halo2VerifierAddress = halo2Verifier.address
        globalPublicParamsAddress = globalPublicParams.address
        pseudoRandAddress = pseudoRand.address
    }

    const Zkdvrf = await ethers.getContractFactory('zkdvrf_pre')
    const zkdvrf = await Zkdvrf.connect(deployerWallet).deploy(threshold, numberOfMembers, adminAddress, halo2VerifierAddress, halo2VerifyingKeyAddress, globalPublicParamsAddress, pseudoRandAddress, minDeposit)
    await zkdvrf.deployed()

    console.log("zkdvrf_pre deployed at", zkdvrf.address)
}

main().then(() => {
    process.exit(0);
})
    .catch((error) => {
        console.error(error);
        process.exitCode = 1;
    });
