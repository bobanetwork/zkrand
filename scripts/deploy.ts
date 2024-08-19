import hre, {artifacts, ethers} from "hardhat";
import {Contract, ContractFactory, providers, utils, Wallet} from "ethers";

async function isContractDeployed(
    contractAddress: string,
    provider: ethers.providers.Provider
): Promise<boolean> {
    let isDeployed = false;

    try {
        // Attempt to get the bytecode of the contract
        const bytecode = await provider.getCode(contractAddress);

        // If the bytecode is '0x', then the contract is not deployed
        if (bytecode !== "0x") {
            isDeployed = true;
        }
    } catch (error) {
        // Log the error for debugging purposes
        console.warn("Error fetching contract code:", error);
        // Set isDeployed to false if there is an error
        isDeployed = false;
    }

    return isDeployed;
}

async function main() {
    const netprovider = new providers.JsonRpcProvider(process.env.L2_NODE_WEB3_URL)
    const accPrivateKey = process.env.DEPLOYER_PRIVATE_KEY ?? ''
    const adminAddress = process.env.ADMIN_ADDRESS ?? ''
    const deployerWallet = new Wallet(accPrivateKey, netprovider)
    const threshold = process.env.THRESHOLD
    const numberOfMembers = process.env.NUMBER_OF_MEMBERS
    const degree = process.env.DEGREE
    const minDeposit = process.env.MIN_DEPOSIT ?? '0'
    const deployPartial = process.env.DEPLOY_PARTIAL === 'true'

    let halo2VerifyingKeyAddress
    let halo2VerifierAddress
    let globalPublicParamsAddress
    let pseudoRandAddress

    if (deployPartial) {
        // use contracts that are already deployed
        // if any contract address is not provided, the contract will be re-deployed
        halo2VerifyingKeyAddress = process.env.HALO2VK
        halo2VerifierAddress = process.env.HALO2V
        globalPublicParamsAddress = process.env.GPP
        pseudoRandAddress = process.env.PSRAND

        // check if contracts are deployed; if not, the contracts will be re-deployed
        if (halo2VerifyingKeyAddress) {
            const isDeployed = await isContractDeployed(halo2VerifyingKeyAddress, netprovider)
            if (!isDeployed) {
                console.warn("Halo2VerifyingKey contract address provided but contract is not deployed or invalid.");
                halo2VerifyingKeyAddress = null
            }
        }

        if (halo2VerifierAddress) {
            const isDeployed = await isContractDeployed(halo2VerifierAddress, netprovider)
            if (!isDeployed) {
                console.warn("Halo2Verifier contract address provided but contract is not deployed or invalid.");
                halo2VerifierAddress = null
            }
        }

        if (globalPublicParamsAddress) {
            const isDeployed = await isContractDeployed(globalPublicParamsAddress, netprovider)
            if (!isDeployed) {
                console.warn("GlobalPublicParams contract address provided but contract is not deployed or invalid.");
                globalPublicParamsAddress = null
            }
        }

        if (pseudoRandAddress) {
            const isDeployed = await isContractDeployed(pseudoRandAddress, netprovider)
            if (!isDeployed) {
                console.warn("PseudoRand contract address provided but contract is not deployed or invalid.");
                pseudoRandAddress = null
            }
        }
    }

    if (!halo2VerifyingKeyAddress) {
        const Halo2VerifyingKey = await ethers.getContractFactory(`contracts/Halo2VerifyingKey-${threshold}-${numberOfMembers}-${degree}-g2.sol:Halo2VerifyingKey`)
        const halo2VerifyingKey = await Halo2VerifyingKey.connect(deployerWallet).deploy()
        await halo2VerifyingKey.deployed()

        console.log("Halo2VerifyingKey (HALO2VK) deployed at", halo2VerifyingKey.address)
        halo2VerifyingKeyAddress = halo2VerifyingKey.address
    }

    if (!halo2VerifierAddress) {
        const Halo2Verifier = await ethers.getContractFactory('contracts/Halo2Verifier.sol:Halo2Verifier')
        const halo2Verifier = await Halo2Verifier.connect(deployerWallet).deploy()
        await halo2Verifier.deployed()

        console.log("Halo2Verifier (HALO2V) deployed at", halo2Verifier.address)
        halo2VerifierAddress = halo2Verifier.address
    }

    if (!globalPublicParamsAddress) {
        const GlobalPublicParams = await ethers.getContractFactory('GlobalPublicParams')
        const globalPublicParams = await GlobalPublicParams.connect(deployerWallet).deploy()
        await globalPublicParams.deployed()

        console.log("GlobalPublicParams (GPP) deployed at", globalPublicParams.address)
        globalPublicParamsAddress = globalPublicParams.address
    }

    if (!pseudoRandAddress) {
        const PseudoRand = await ethers.getContractFactory('PseudoRand')
        const pseudoRand = await PseudoRand.connect(deployerWallet).deploy()
        await pseudoRand.deployed()

        console.log("PseudoRand (PSRAND) deployed at", pseudoRand.address)
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
