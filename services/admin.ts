/* Imports: External */
import {BigNumber, Contract, Wallet, providers} from 'ethers'
import fs from "fs";
import {promisify} from "util";
import {exec} from "child_process";
import {sleep} from '@eth-optimism/core-utils'
import {BaseService} from '@eth-optimism/common-ts'

import zkRandContractABI from '../artifacts/contracts/zkdvrf_pre.sol/zkdvrf_pre.json'

export const memberDir = `./data/members/`
export const mpksPath = `./data/mpks.json`
export const dkgDir = `./data/dkg/`
export const instancesPath = `./data/dkg/all_instances.json`
export const randDir = `./data/random/`

enum Status {
    Unregistered = 0,
    Registered = 1,
    Nidkg = 2,
    NidkgComplete = 3,
    Ready = 4
}

interface Eval {
    indexPlus: number
}

export interface GasPriceOverride {
    gasLimit: number
    gasPrice?: number
}

interface AdminZkRandOptions {
    threshold: number
    numberMembers: number
    degree: number
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
    randGenInterval: number
    randGenStartDate: string
}

const optionSettings = {}

const emptyAddress = '0x0000000000000000000000000000000000000000'
// String representation of bytes32(0)
const bytes32Zero = "0x" + "0".repeat(64);
const gasLimitLow = 500000
const gasLimitHigh = 3000000
const zero = BigNumber.from(0);

export class AdminZkRandService extends BaseService<AdminZkRandOptions> {
    constructor(options: AdminZkRandOptions) {
        super('AdminZkRandService', options, optionSettings)
    }

    private state: {
        zkRandContract: Contract
        gasOverride: GasPriceOverride
        timeOfLastRound: number
        startDate: number
    } = {} as any

    private cmdPrefix: string;

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

        this.state.gasOverride = {gasLimit: 10000000}
        this.state.timeOfLastRound = 0 // 0 indicates no round has been initiated

        this.state.startDate = 0
        let startDate = new Date(this.options.randGenStartDate)
        if (!isNaN(startDate.getTime())) {
            this.state.startDate = startDate.getTime()
        }

        this.cmdPrefix = `RUST_LOG=info THRESHOLD=${this.options.threshold} NUMBER_OF_MEMBERS=${this.options.numberMembers} DEGREE=${this.options.degree} /usr/local/bin/client`

        await this.check_config()
    }

    async _start(): Promise<void> {
        console.log('\n------------------------------ admin starts ------------------------------')

        const adminFromContract = await this.state.zkRandContract.owner()
        console.log("admin in contract:", adminFromContract)
        if (adminFromContract !== this.options.l2Wallet.address) {
            throw new Error(
                `ADMIN_PRIVATE_KEY is not set to zkRand admin ${adminFromContract}`
            )
        }

        const currentIndexFromContract = await this.state.zkRandContract.currentIndex()
        console.log("currentIndexFromContract", currentIndexFromContract)

        if (currentIndexFromContract != this.options.numberMembers) {
            // check if nidkg is already completed, or if this step is already done
            console.log("adding permissioned nodes")
            const nodeOne = await this.state.zkRandContract.addrToNode(this.options.nodeOneAddress)
            if (nodeOne.nodeAddress === emptyAddress) {
                const retOne = await this.state.zkRandContract.addPermissionedNodes(this.options.nodeOneAddress, {gasLimit: gasLimitLow})
                console.log("transaction hash for addPermissionedNodes on node one:", retOne.hash)
                await retOne.wait()
            }

            const nodeTwo = await this.state.zkRandContract.addrToNode(this.options.nodeTwoAddress)
            if (nodeTwo.nodeAddress === emptyAddress) {
                const retTwo = await this.state.zkRandContract.addPermissionedNodes(this.options.nodeTwoAddress, {gasLimit: gasLimitLow})
                console.log("transaction hash for addPermissionedNodes on node two:", retTwo.hash)
                await retTwo.wait()
            }

            const nodeThree = await this.state.zkRandContract.addrToNode(this.options.nodeThreeAddress)
            if (nodeThree.nodeAddress === emptyAddress) {
                const retThree = await this.state.zkRandContract.addPermissionedNodes(this.options.nodeThreeAddress, {gasLimit: gasLimitLow})
                console.log("transaction hash for addPermissionedNodes on node three:", retThree.hash)
                await retThree.wait()
            }

            const nodeFour = await this.state.zkRandContract.addrToNode(this.options.nodeFourAddress)
            if (nodeFour.nodeAddress === emptyAddress) {
                const retFour = await this.state.zkRandContract.addPermissionedNodes(this.options.nodeFourAddress, {gasLimit: gasLimitLow})
                console.log("transaction hash for addPermissionedNodes on node four:", retFour.hash)
                await retFour.wait()
            }

            const nodeFive = await this.state.zkRandContract.addrToNode(this.options.nodeFiveAddress)
            if (nodeFive.nodeAddress === emptyAddress) {
                const retFive = await this.state.zkRandContract.addPermissionedNodes(this.options.nodeFiveAddress, {gasLimit: gasLimitLow})
                console.log("transaction hash for addPermissionedNodes on node five:", retFive.hash)
                await retFive.wait()
            }
        }

        while (this.running) {
            try {
                const contractPhase = await this.state.zkRandContract.contractPhase()
                console.log("contractPhase", contractPhase)
                if (contractPhase == Status.Registered) {
                    // all the nodes have registered; start nidkg
                    const ret = await this.state.zkRandContract.startNidkg({gasLimit: gasLimitLow})
                    console.log("transaction hash for startNiDkg:", ret.hash)
                    await ret.wait()
                } else if (contractPhase == Status.NidkgComplete) {
                    // nidkg has completed; calculate global public parameters
                    await this.createGpp()
                } else if (contractPhase == Status.Ready) {
                    const currentRoundNum: BigNumber = await this.state.zkRandContract.currentRoundNum()
                    console.log("currentRoundNum", currentRoundNum.toString())
                    if (Date.now() < this.state.startDate) {
                        const begin = new Date(this.state.startDate);
                        console.log("randomness generation will begin at", begin.toUTCString())
                    } else {
                        if (currentRoundNum.eq(zero)) {
                            // random generation starts from 1
                            await this.initiateRand()
                        } else {
                            const submissionCount = await this.state.zkRandContract.roundSubmissionCount(currentRoundNum)
                            const roundToRandom = await this.state.zkRandContract.roundToRandom(currentRoundNum)

                            if (roundToRandom.value === bytes32Zero && submissionCount >= this.options.threshold) {
                                await this.createRandom(currentRoundNum)
                            }

                            const secondsElapsed = Math.floor(
                                (Date.now() - this.state.timeOfLastRound) / 1000
                            )
                            console.log('Seconds elapsed since last random initiation:', secondsElapsed)

                            if (secondsElapsed > this.options.randGenInterval && roundToRandom.value !== bytes32Zero) {
                                await this.initiateRand();
                            }
                        }
                    }
                }
            } catch (error) {
                console.warn("admin script error:", error)
            }

            await sleep(this.options.pollingInterval)
        }
    }

    async listenRegister() {
        // check if already registered and skip if true
        const eventReg = `RegistrationCompleted`
        this.state.zkRandContract.on(eventReg, async (count, event) => {
            console.log("\nevent", eventReg, count);
            // Proceed to the next step here
            const ret = await this.state.zkRandContract.startNidkg({gasLimit: gasLimitLow})
            console.log("transaction hash for startNiDkg: ", ret.hash)
            await ret.wait()
        });
    }

    async listenNidkg() {
        // This will run when the event is emitted
        const eventDkg = `NidkgCompleted`
        this.state.zkRandContract.on(eventDkg, async (count, event) => {
            console.log("\nevent", eventDkg, count);
            // read all instances from contract
            const ppList = await this.state.zkRandContract.getPpList()
            // save ppList for rust backend
            const ppListHex = ppList.map(subList =>
                subList.map(num => num.toHexString())
            );
            const obj = JSON.stringify(ppListHex)
            await waitForWriteJsonToFile(obj, instancesPath)
            console.log("retrieved all instances from contract")
            console.log("sleeping..")
            await sleep(5000)

            // derive global public parameters
            const cmd = `${this.cmdPrefix} dkg derive`
            console.log("running command <", cmd, ">...")
            let result = await execPromise(cmd)
            console.log(result[`stderr`])

            const filePath = dkgDir + "gpk.json"
            const gpk = readJsonFromFile(filePath);

            const res = await this.state.zkRandContract.computeVk(gpk, {gasLimit: gasLimitHigh})
            console.log("transaction hash for computeVk: ", res.hash)
            await res.wait()

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

    async check_config() {
        const threshold = await this.state.zkRandContract.threshold()
        if (threshold != this.options.threshold) {
            throw new Error(
                `threshold=${this.options.threshold} does not match threshold=${threshold} from contract`
            )
        }
        const memberCountFromContract = await this.state.zkRandContract.memberCount()
        if (memberCountFromContract != this.options.numberMembers) {
            throw new Error(
                `number_of_members=${this.options.numberMembers} does not match number_of_members=${memberCountFromContract} from contract`
            )
        }
        console.log("memberCountFromContract", memberCountFromContract)
    }


    async createGpp() {
        // read all instances from contract
        const ppList = await this.state.zkRandContract.getPpList()
        // save ppList for rust backend
        const ppListHex = ppList.map(subList =>
            subList.map(num => num.toHexString())
        );
        const obj = JSON.stringify(ppListHex)
        await waitForWriteJsonToFile(obj, instancesPath)
        console.log("retrieved all instances from contract")
        console.log("sleeping..")
        await sleep(5000)

        // derive global public parameters
        const cmd = `${this.cmdPrefix} dkg derive`
        console.log("running command <", cmd, ">...")
        const result = await execPromise(cmd)
        console.log(result[`stderr`])

        const filePath = dkgDir + "gpk.json"
        const gpk = readJsonFromFile(filePath);

        const res = await this.state.zkRandContract.computeVk(gpk, {gasLimit: gasLimitHigh})
        console.log("transaction hash for computeVk: ", res.hash)
        await res.wait()

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
    }

    async initiateRand() {
        // Proceed to the next step here
        const res = await this.state.zkRandContract.initiateRandom({gasLimit: gasLimitLow})
        console.log("transaction hash for initiateRandom: ", res.hash)
        await res.wait()
        this.state.timeOfLastRound = Date.now()
        const currentDate = new Date(this.state.timeOfLastRound);
        console.log("******** new random round begins at:", currentDate.toUTCString(), "********")
    }

    async listenRandThreshold() {
        const eventRandThreshold = `RandomThresholdReached`
        this.state.zkRandContract.on(eventRandThreshold, async (roundNum, input, event) => {
            console.log("\nevent", eventRandThreshold, `round ${roundNum} input "${input}"`)

            const memberCountFromContract = await this.state.zkRandContract.memberCount()
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
            console.log("sleeping..")
            await sleep(2000)

            const cmdCombine = `${this.cmdPrefix} rand combine "${input}"`
            console.log("running command <", cmdCombine, ">...")
            let result = await execPromise(cmdCombine)
            console.log(result[`stderr`])

            const cmdVerify = `${this.cmdPrefix} rand verify-final "${input}"`
            console.log("running command <", cmdVerify, ">...")
            result = await execPromise(cmdVerify)
            console.log(result[`stderr`])

            const pseudoPath = randDir + `pseudo.json`
            const pseudo = readJsonFromFile(pseudoPath)
            console.log("pseudorandom computed", '0x' + Buffer.from(pseudo[`value`]).toString('hex'))

            const res = await this.state.zkRandContract.submitRandom(pseudo, {gasLimit: gasLimitLow})
            console.log("transaction hash for submitRandom:", res.hash)
            await res.wait()

            const rand = await this.state.zkRandContract.getLatestRandom()
            console.log("✅ pseudorandom from contract", rand.value)
        });
    }

    async createRandom(roundNum: BigNumber) {
        const memberCountFromContract = await this.state.zkRandContract.memberCount()
        const input = await this.state.zkRandContract.roundInput(roundNum)

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
        console.log("sleep..")
        await sleep(2000)

        const cmdCombine = `${this.cmdPrefix} rand combine "${input}"`
        console.log("running command <", cmdCombine, ">...")
        let result = await execPromise(cmdCombine)
        console.log(result[`stderr`])

        const cmdVerify = `${this.cmdPrefix} rand verify-final "${input}"`
        console.log("running command <", cmdVerify, ">...")
        result = await execPromise(cmdVerify)
        console.log(result[`stderr`])

        const pseudoPath = randDir + `pseudo.json`
        const pseudo = readJsonFromFile(pseudoPath)
        console.log("pseudorandom computed", '0x' + Buffer.from(pseudo[`value`]).toString('hex'))

        const res = await this.state.zkRandContract.submitRandom(pseudo, {gasLimit: gasLimitLow})
        console.log("transaction hash for submitRandom:", res.hash)
        await res.wait()
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