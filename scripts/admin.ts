import hre, {artifacts, ethers} from "hardhat";
import {Contract, ContractFactory, providers, utils, Wallet} from "ethers";
import {
    dkgDir,
    execPromise,
    instancesPath,
    memberDir, randDir,
    readJsonFromFile,
    sleep,
    waitForWriteJsonToFile,
    writeJsonToFile
} from "./utils";
import { createInterface } from "readline";

const config = readJsonFromFile("demo-config.json")
const zkdvrfAddress = config.zkdvrfAddress
const memberAdresses = config.memberAddresses

interface Eval {
    indexPlus: number
}

async function main() {
    const netprovider = new providers.JsonRpcProvider(process.env.RPC_URL)
    const accPrivateKey = process.env.PRIVATE_KEY ?? ''
    const adminWallet = new Wallet(accPrivateKey, netprovider)

    const Zkdvrf = await ethers.getContractFactory('zkdvrf')
    const contractABI = Zkdvrf.interface.format();
    const contract = new ethers.Contract(zkdvrfAddress, contractABI, netprovider).connect(adminWallet)

    const restart = process.env.RESTART === 'true'

    const rl = createInterface({
        input: process.stdin,
        output: process.stdout
    });

    if (!restart) {
        for (let i = 0; i < memberAdresses.length; i++) {
            const res = await contract.addPermissionedNodes(memberAdresses[i])
           // console.log(res)
            console.log("added member", memberAdresses[i])
        }
    }

    async function listenRegister() {
        // This will run when the event is emitted
        const eventReg = `RegistrationCompleted`
        contract.on(eventReg, async (count, event) => {
            console.log("\nevent", eventReg, count);
            // Proceed to the next step here
            const res = await contract.startNidkg()
            const receipt = await netprovider.getTransactionReceipt(res.hash);
            // Check if the transaction was successful
            if (receipt.status === 1) {
                console.log("Transaction startNidkg() successful!");
            } else {
                console.log("Transaction startNidkg() failed!");
            }
            console.log("NIDKG begins...")
        });
    }

    if (!restart) {
        listenRegister()
    }

    async function listenNidkg() {
        // This will run when the event is emitted
        const eventDkg = `NidkgCompleted`
        contract.on(eventDkg, async (count, event) => {
            console.log("\nevent", eventDkg, count);
            // read all instances from contract
            const ppList = await contract.getPpList()
           // console.log("\nppList = ", ppList)
            // save ppList for rust backend
            const ppListHex = ppList.map(subList =>
                subList.map(num => num.toHexString())
            );
            const obj = JSON.stringify(ppListHex)
            await waitForWriteJsonToFile(obj, instancesPath)
            //console.log("retrieved all instances from contract")


            console.log("begin sleep")
            await sleep(2000)
            console.log("end sleep")


            // derive global public parameters
            const cmd = `RUST_LOG=info ./target/release/client dkg derive`
            let result = await execPromise(cmd)
            console.log(result[`stderr`])

            const filePath = dkgDir + "gpk.json"
            const gpk = readJsonFromFile(filePath);

            const res = await contract.computeVk(gpk)
            const receipt = await netprovider.getTransactionReceipt(res.hash);
            // Check if the transaction was successful
            if (receipt.status === 1) {
                console.log("Transaction computeVk(..) successful!");
            } else {
                console.log("Transaction computeVk(..) failed!");
            }

            // read global public parameters from the contract and compare them with the local version
            const gpkVal = await contract.getGpk()
            if (BigInt(gpk.x[0]) != gpkVal.x[0] || BigInt(gpk.x[1]) != gpkVal.x[1]
                || BigInt(gpk.y[0]) != gpkVal.y[0] || BigInt(gpk.y[1]) != gpkVal.y[1]) {
                console.error("gpk doesn't match")
            }

            const vkList = await contract.getVkList()
            const vks = readJsonFromFile(dkgDir + "vks.json")

            if (vkList.length != vks.length) {
                console.error("vk list length does not match")
            }

            // Check if each element at corresponding indices is equal
            for (let i = 0; i < vks.length; i++) {
                if (BigInt(vks[i].x) != vkList[i].x || BigInt(vks[i].y) != vkList[i].y) {
                    console.error(`vk list does not match on ${i}-th vk`)
                }
            }
        });
    }

    if (!restart) {
        listenNidkg()
    }

    async function initiateRand(eventReceived) {
        console.log("\nevent received ", eventReceived)
        // Proceed to the next step here
        const res = await contract.initiateRandom()
        const receipt = await netprovider.getTransactionReceipt(res.hash);
        // Check if the transaction was successful
        if (receipt.status === 1) {
            console.log("Transaction initiateRandom() successful!");
        } else {
            console.log("Transaction initiateRandom() failed!");
        }

        console.log('\n 🔔 Please continue by running \'yarn random\' on a new terminal to submit partial evals...')
    }

    // start listening for the event
    if (!restart) {
        const eventGpp = `GlobalPublicParamsCreated`
        contract.on(eventGpp, async (event) => {
            await initiateRand(eventGpp);
        });
    }

    async function listenRandThreshold() {
        const eventRandThreshold = `RandomThresholdReached`
        contract.on(eventRandThreshold, async (roundNum, input, event) => {
            console.log("\nevent", eventRandThreshold, `round ${roundNum} input ${input}`)

            console.log("begin sleep...")
            await sleep(2000)
            console.log("end sleep")

            const evals: Eval[] = []
            for (let i = 0; i < memberAdresses.length; i++) {
                const evalFromContract = await contract.roundToEval(roundNum, i)
                if (evalFromContract.indexPlus != 0) {
                    evals.push(evalFromContract)
                }
            }

            const pEvals = []
            for (let i = 0; i < evals.length; i++) {
                const index = evals[i][0]
                const value = {x: evals[i][1][0].toHexString(), y: evals[i][1][1].toHexString()}
                const proof = {z: evals[i][2][0].toHexString(), c: evals[i][2][1].toHexString()}

               const sigma = {
                   index: index,
                   value: value,
                   proof: proof,
               }

               pEvals.push(sigma)
            }

            const obj = JSON.stringify(pEvals)
            const evalsPath = randDir + `evals.json`
            await waitForWriteJsonToFile(obj, evalsPath)

            console.log("begin sleep...")
            await sleep(2000)
            console.log("end sleep")

            const cmdCombine = `RUST_LOG=info ./target/release/client rand combine ${input}`
            console.log("running command <", cmdCombine, ">...")
            let result = await execPromise(cmdCombine)
            console.log(result[`stderr`])

            const cmdVerify = `RUST_LOG=info ./target/release/client rand verify-final ${input}`
            console.log("running command <", cmdVerify, ">...")
            result = await execPromise(cmdVerify)
            console.log(result[`stderr`])

            const pseudoPath = randDir + `pseudo.json`
            const pseudo = readJsonFromFile(pseudoPath)
            console.log("pseudorandom computed", '0x' + Buffer.from(pseudo[`value`]).toString('hex'))

            const res = await contract.submitRandom(pseudo)
            const receipt = await netprovider.getTransactionReceipt(res.hash);
            // Check if the transaction was successful
            if (receipt.status === 1) {
                console.log("Transaction submitRandom(..) successful!");
            } else {
                console.log("Transaction submitRandom(..) failed!");
            }

            const rand = await contract.getLatestRandom()
            console.log("✅ pseudorandom from contract", rand.value)
        });
    }

    listenRandThreshold()

    // start listening for event
    const eventRandReady = `RandomReady`
    contract.on(eventRandReady,  async (roundNum, roundInput, event) => {
        rl.question("\n 🔔 Do you want to initiate random again? (yes/no): ", async (answer) => {
            if (answer.toLowerCase() === "yes") {
                await initiateRand(eventRandReady);
            } else {
                console.log("Exiting the process...");
                process.exit(0);
            }
        });
    });
}


main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
