import hre, {artifacts, ethers} from "hardhat";
import {Contract, ContractFactory, providers, utils, Wallet} from "ethers";
import { promisify } from 'util';
import { exec } from "child_process";
import {readJsonFromFile, writeJsonToFile, memberDir, mpksPath, execPromise, randDir} from "./utils";

const config = readJsonFromFile("demo-config.json")
const zkdvrfAddress = config.zkdvrfAddress
const memberKeys = config.memberKeys

async function main() {
    const netprovider = new providers.JsonRpcProvider(process.env.RPC_URL)

    const Zkdvrf = await ethers.getContractFactory('zkdvrf')
    const contractABI = Zkdvrf.interface.format();
    const contract = new ethers.Contract(zkdvrfAddress, contractABI, netprovider);

    const currentRound = await contract.currentRoundNum()
    console.log("current round number = ", currentRound)
    const input = await contract.roundInput(currentRound)
    console.log("current input = ", input)

    //Members creates partial evaluations
    for (let i = 0; i < memberKeys.length; i++) {
        const memberWallet = new Wallet(memberKeys[i], netprovider)
        const memberAddress = memberWallet.address
        const memberContract = contract.connect(memberWallet)

        const index = await memberContract.getIndexPlus(memberAddress)
        const cmdEval = `RUST_LOG=info ./target/release/client rand eval ${index} ${input}`
        const cmdVerify = `RUST_LOG=info ./target/release/client rand verify ${index} ${input}`

        console.log("running command <", cmdEval, ">...")
        let result = await execPromise(cmdEval)
        console.log(result[`stderr`])

        console.log("running command <", cmdVerify, ">...")
        result = await execPromise(cmdVerify)
        console.log(result[`stderr`])

        const evalPath = randDir + `eval_${index}.json`
        const evalJson = readJsonFromFile(evalPath)
        const pEval = {
            indexPlus: evalJson[`index`],
            value: evalJson[`value`],
            proof: evalJson[`proof`]
        }

        const res = await memberContract.submitPartialEval(pEval)
        const receipt = await netprovider.getTransactionReceipt(res.hash);
        // Check if the transaction was successful
        if (receipt.status === 1) {
            console.log(`Transaction submitPartialEval(..) from member ${memberAddress} successful!`);
        } else {
            console.log(`Transaction submitPartialEval(..) from member ${memberAddress} failed!`);
        }
    }

}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});