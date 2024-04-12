import hre, {artifacts, ethers} from "hardhat";
import {Contract, ContractFactory, providers, utils, Wallet} from "ethers";
import {
    readJsonFromFile,
    writeJsonToFile,
    memberDir,
    mpksPath,
    dkgDir,
    readBytesFromFile,
    execPromise,
    instancesPath,
    waitForWriteJsonToFile
} from "./utils";


const config = readJsonFromFile("demo-config.json")
const zkdvrfAddress = config.zkdvrfAddress
const memberKeys = config.memberKeys
async function main() {
    const netprovider = new providers.JsonRpcProvider(process.env.RPC_URL)

    const Zkdvrf = await ethers.getContractFactory('zkdvrf')
    const contractABI = Zkdvrf.interface.format();
    const contract = new ethers.Contract(zkdvrfAddress, contractABI, netprovider);

    // get all members' indices from contract
    const indices = [];
    for (let i = 0; i < memberKeys.length; i++) {
        const memberWallet = new Wallet(memberKeys[i], netprovider)
        const memberAddress = memberWallet.address

        const index = await contract.getIndexPlus(memberAddress)
        indices.push(index)
    }

    // This will run when the event is emitted
    async function listenNidkg() {
        const eventName = `NidkgCompleted`
        contract.on(eventName, async (count, event) => {
            console.log("\nevent", eventName, count)

            // read all instances from contract
            const ppList = await contract.getPpList()
            // save ppList for rust backend
            const ppListHex = ppList.map(subList =>
                subList.map(num => num.toHexString())
            );
            const obj = JSON.stringify(ppListHex)
            await waitForWriteJsonToFile(obj, instancesPath)

            // each member derives its own secret share and global public parameters
            const cmd = `RUST_LOG=info ./target/release/client dkg derive`
            for (let i = 0; i < memberKeys.length; i++) {
                const index = indices[i]
                const cmdMember = cmd + ` ${index} -f member_${i+1}`
                console.log("running command <", cmdMember, ">...")
                const res =  await execPromise(cmdMember)
                console.log(res[`stderr`])
            }

            process.exit(0);
            // todo: compare the local global public parameters with the one from the contract
        });
    }

    listenNidkg();

    const total = memberKeys.length;
//    const total = 1;
    for (let i = 0; i < total; i++) {
        const memberWallet = new Wallet(memberKeys[i], netprovider)
        const memberAddress = memberWallet.address
        const memberContract = contract.connect(memberWallet)

        const cmdProve = `RUST_LOG=info ./target/release/client dkg prove ${indices[i]}`
        const cmdVerify = `RUST_LOG=info ./target/release/client dkg verify ${indices[i]}`

        // generate snark proof and instance
        console.log("running command <", cmdProve, ">...")
        let result = await execPromise(cmdProve)
        console.log(result[`stderr`])

        // verify snark proof and instance
        console.log("running command <", cmdVerify, ">...")
        result = await execPromise(cmdVerify)
        console.log(result[`stdout`])

        // read snark proof and instance
        const proofPath = dkgDir + `proofs/proof_${indices[i]}.dat`
        const instancePath = dkgDir + `proofs/instance_${indices[i]}.json`

        const proof = readBytesFromFile(proofPath)
        const instance = readJsonFromFile(instancePath)

        // submit proof and instance to contract
        const res = await memberContract.submitPublicParams(instance, proof)
        const receipt = await netprovider.getTransactionReceipt(res.hash);
        // Check if the transaction was successful
        if (receipt.status === 1) {
            console.log(`Transaction submitPublicParams(..) from ${memberAddress} successful!`);
        } else {
            console.log(`Transaction submitPublicParams(..) from ${memberAddress} failed!`);
        }

    }

}


main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});

