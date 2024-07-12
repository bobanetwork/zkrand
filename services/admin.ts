/* Imports: External */
import { Contract, Wallet, BigNumber, providers } from 'ethers'
import fs from "fs";
import {promisify} from "util";
import {exec} from "child_process";

import { sleep } from '@eth-optimism/core-utils'
import { BaseService } from '@eth-optimism/common-ts'

import zkRandContractABI from '../artifacts/contracts/zkdvrf.sol/zkdvrf.json'

export const memberDir = `./data/members/`
export const mpksPath = `./data/mpks.json`
export const dkgDir = `./data/dkg/`
export const instancesPath = `./data/dkg/all_instances.json`
export const randDir = `./data/random/`

interface Eval {
    indexPlus: number
}

export interface GasPriceOverride {
    gasLimit: number
    gasPrice?: number
  }

interface AdminZkRandOptions {
  l2RpcProvider: providers.StaticJsonRpcProvider
  l2Wallet: Wallet
  // chain ID of the L2 network
  chainId: number

  zkRandAddress: string

  nodeOneAddress: string
  nodeTwoAddress: string
  nodeThreeAddress: string
  nodeFourAddress: string
  nodeFiveAddress: string

  pollingInterval: number
}

const optionSettings = {}

export class AdminZkRandService extends BaseService<AdminZkRandOptions> {
  constructor(options: AdminZkRandOptions) {
    super('AdminZkRandService', options, optionSettings)
  }

  private state: {
    zkRandContract: Contract
    gasOverride: GasPriceOverride
    timeOfLastRound: number
  } = {} as any

  async _init(): Promise<void> {
    this.logger.info('Initializing AdminZkRand service...', {
      options: this.options,
    })

    this.logger.info('Connecting to ZkRand contract...', {
      bobaLinkPairs: this.options.zkRandAddress,
    })

    this.state.zkRandContract = new Contract(
        this.options.zkRandAddress,
        zkRandContractABI.abi,
        this.options.l2Wallet
      )
  
    this.logger.info('Connected to ZkRand contract', {
        address: this.state.zkRandContract.address,
        chainId: this.options.chainId,
        rpc: this.state.zkRandContract.provider,
    })

    this.state.gasOverride = { gasLimit: 10000000 }
    this.state.timeOfLastRound = 0 // 0 indicates no round has been initiated
  }

  async _start(): Promise<void> {
    console.log('started')

    let adminFromContract = await this.state.zkRandContract.owner()
    console.log(adminFromContract)

    if (adminFromContract !== this.options.l2Wallet.address) {
        throw new Error(
        `ADMIN_PRIVATE_KEY is not set to zkRand admin ${adminFromContract}`
        )
    }

    let memberCountFromContract = await this.state.zkRandContract.memberCount()
    console.log(memberCountFromContract)
    let currentIndexFromContract = await this.state.zkRandContract.currentIndex()
    console.log(currentIndexFromContract)

    // TODO: handle the case where only some members have been added
    if (currentIndexFromContract != memberCountFromContract) {
        // check if nidkg is already completed, or if this step is already done
        const retOne = await this.state.zkRandContract.addPermissionedNodes(this.options.nodeOneAddress)
        await retOne.wait()
        const retTwo = await this.state.zkRandContract.addPermissionedNodes(this.options.nodeTwoAddress)
        await retTwo.wait()
        const retThree = await this.state.zkRandContract.addPermissionedNodes(this.options.nodeThreeAddress)
        await retThree.wait()
        const retFour = await this.state.zkRandContract.addPermissionedNodes(this.options.nodeFourAddress)
        await retFour.wait()
        const retFive = await this.state.zkRandContract.addPermissionedNodes(this.options.nodeFiveAddress)
        await retFive.wait()
    }

    while (this.running) {
        let contractPhase = await this.state.zkRandContract.contractPhase()
        console.log(contractPhase)
        if (contractPhase < 2) {
            // register when all nodes have added themselves
            // check if already registed, and skip
            await this.listenRegister()

            // check if nidkg is complete and skip
            await this.listenNidkg()
        }

        // TODO: need an if here to allow skipping on the second pass
        const eventGpp = `GlobalPublicParamsCreated`
        this.state.zkRandContract.on(eventGpp, async (event) => {
            await this.initiateRand();
        });

        let secondsElapsed: number
        if (this.state.timeOfLastRound == 0) {
            secondsElapsed = 0
            console.log('Still waiting on GPP creation')
        } else {
            secondsElapsed = Math.floor(
                (Date.now() - this.state.timeOfLastRound) / 1000
            )
            console.log('Seconds elapsed since last random initiation:', secondsElapsed)
        }

        if (secondsElapsed > 3600) {
            await this.initiateRand();
        }


        await this.listenRandThreshold()
        
        await sleep(this.options.pollingInterval)
    }
  }

  async listenRegister() {
    // check if already registered and skip if true
    const eventReg = `RegistrationCompleted`
    this.state.zkRandContract.on(eventReg, async (count, event) => {
        console.log("\nevent", eventReg, count);
        // Proceed to the next step here
        const res = await this.state.zkRandContract.startNidkg()
        const receipt = await this.options.l2RpcProvider.getTransactionReceipt(res.hash);
        // Check if the transaction was successful
        if (receipt.status === 1) {
            console.log("Transaction startNidkg() successful!");
        } else {
            console.log("Transaction startNidkg() failed!");
        }
        console.log("NIDKG begins...")
    });
  }

  async listenNidkg() {
    // This will run when the event is emitted
    const eventDkg = `NidkgCompleted`
    this.state.zkRandContract.on(eventDkg, async (count, event) => {
        console.log("\nevent", eventDkg, count);
        // read all instances from contract
        const ppList = await this.state.zkRandContract.getPpList()
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
        console.log("running command <", cmd, ">...")
        let result = await execPromise(cmd)
        console.log(result[`stderr`])

        const filePath = dkgDir + "gpk.json"
        const gpk = readJsonFromFile(filePath);

        const res = await this.state.zkRandContract.computeVk(gpk)
        const receipt = await this.options.l2RpcProvider.getTransactionReceipt(res.hash);
        // Check if the transaction was successful
        if (receipt.status === 1) {
            console.log("Transaction computeVk(..) successful!");
        } else {
            console.log("Transaction computeVk(..) failed!");
        }

        // read global public parameters from the contract and compare them with the local version
        const gpkVal = await this.state.zkRandContract.getGpk()
        if (BigInt(gpk.x[0]) != gpkVal.x[0] || BigInt(gpk.x[1]) != gpkVal.x[1]
            || BigInt(gpk.y[0]) != gpkVal.y[0] || BigInt(gpk.y[1]) != gpkVal.y[1]) {
            console.error("gpk doesn't match")
        }

        const vkList = await this.state.zkRandContract.getVkList()
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

  async initiateRand() {
    // Proceed to the next step here
    const res = await this.state.zkRandContract.initiateRandom()
    const receipt = await this.options.l2RpcProvider.getTransactionReceipt(res.hash);
    // Check if the transaction was successful
    if (receipt.status === 1) {
        console.log("Transaction initiateRandom() successful!");
        this.state.timeOfLastRound = Date.now()
    } else {
        console.log("Transaction initiateRandom() failed!");
    }

  }

  async listenRandThreshold() {
    const eventRandThreshold = `RandomThresholdReached`
    this.state.zkRandContract.on(eventRandThreshold, async (roundNum, input, event) => {
        console.log("\nevent", eventRandThreshold, `round ${roundNum} input "${input}"`)

        console.log("begin sleep...")
        await sleep(2000)
        console.log("end sleep")

        let memberCountFromContract = await this.state.zkRandContract.memberCount()
        const evals: Eval[] = []
        for (let i = 0; i < memberCountFromContract; i++) {
            const evalFromContract = await this.state.zkRandContract.roundToEval(roundNum, i)
            if (evalFromContract.indexPlus != 0) {
                evals.push(evalFromContract)
            }
        }

        const pEvals: any = []
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

        const cmdCombine = `RUST_LOG=info ./target/release/client rand combine "${input}"`
        console.log("running command <", cmdCombine, ">...")
        let result = await execPromise(cmdCombine)
        console.log(result[`stderr`])

        const cmdVerify = `RUST_LOG=info ./target/release/client rand verify-final "${input}"`
        console.log("running command <", cmdVerify, ">...")
        result = await execPromise(cmdVerify)
        console.log(result[`stderr`])

        const pseudoPath = randDir + `pseudo.json`
        const pseudo = readJsonFromFile(pseudoPath)
        console.log("pseudorandom computed", '0x' + Buffer.from(pseudo[`value`]).toString('hex'))

        const res = await this.state.zkRandContract.submitRandom(pseudo)
        const receipt = await this.options.l2RpcProvider.getTransactionReceipt(res.hash);
        // Check if the transaction was successful
        if (receipt.status === 1) {
            console.log("Transaction submitRandom(..) successful!");
        } else {
            console.log("Transaction submitRandom(..) failed!");
        }

        const rand = await this.state.zkRandContract.getLatestRandom()
        console.log("✅ pseudorandom from contract", rand.value)
    });
  }
}

export function waitForWriteJsonToFile(obj: string, filePath: string) {
    return new Promise<void>((resolve, reject) => {
        writeJsonToFile(obj, filePath, () => {
            console.log(`JSON file has been saved at ${filePath}`);
            resolve();
        });
    });
}

export function writeJsonToFile(obj: string, filePath: string, callback: () => void) {
    // Write the JSON string to a file
    fs.writeFile(filePath, obj, 'utf8', callback);
}

export const execPromise = promisify(exec);
export function readJsonFromFile(filePath: string): any {
    try {
        // Read file content
        let rawdata = fs.readFileSync(filePath, 'utf-8');

        // Parse JSON
        let jsonData = JSON.parse(rawdata);

        return jsonData;
    } catch (error) {
        console.error(error);
        return null;
    }
}