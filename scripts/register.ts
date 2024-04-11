import hre, {artifacts, ethers} from "hardhat";
import {Contract, ContractFactory, providers, utils, Wallet} from "ethers";
import { promisify } from 'util';
import { exec } from "child_process";
import {readJsonFromFile, writeJsonToFile, memberDir, mpksPath, execPromise} from "./utils";

const config = readJsonFromFile("demo-config.json")
const zkdvrfAddress = config.zkdvrfAddress
const memberKeys = config.memberKeys

async function main() {
    const netprovider = new providers.JsonRpcProvider(process.env.RPC_URL)

    const Zkdvrf = await ethers.getContractFactory('zkdvrf')
    const contractABI = Zkdvrf.interface.format();
    const contract = new ethers.Contract(zkdvrfAddress, contractABI, netprovider);

    // This will run when the event is emitted
    const eventName = `RegistrationCompleted`
    contract.on(eventName, async (count, event) => {
        console.log("event", eventName, count);
        // Proceed to the next step here
        const res = await contract.getPkList()
        console.log("downloaded all member public keys from contract")

        const pks = res.map(pk => ({x: pk[0].toHexString(), y: pk[1].toHexString()}))
        const obj = JSON.stringify(pks);
        writeJsonToFile(obj, mpksPath)
    });


    for (let i = 0; i < memberKeys.length; i++) {
        const memberWallet = new Wallet(memberKeys[i], netprovider)
        const memberAddress = memberWallet.address
        const memberContract = contract.connect(memberWallet)

        // generate member secret key and member public key on grumpkin curve
        const index = i+1
        const file = `member_${index}`
        const command = `RUST_LOG=info ./target/release/client keygen -f ${file}`

        const result = await execPromise(command);
        console.log(result[`stderr`]);

        const filePath = memberDir + file + ".json"
        const data = readJsonFromFile(filePath);
        const mpk = data[`pk`]

        const res = await memberContract.registerNode(mpk)
        const receipt = await netprovider.getTransactionReceipt(res.hash);
        // Check if the transaction was successful
        if (receipt.status === 1) {
            console.log(`Transaction registerNode(..) from ${memberAddress} successful!`);
        } else {
            console.log(`Transaction registerNode(..) from ${memberAddress} failed!`);
        }
        console.log("member ", index, "registered\n")
    }

}

main().then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
