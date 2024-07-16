/* Imports: External */
import {Contract, Wallet, providers} from 'ethers'
import fs from "fs";
import {promisify} from "util";
import {exec} from "child_process";

import {sleep} from '@eth-optimism/core-utils'
import {BaseService} from '@eth-optimism/common-ts'

import zkRandContractABI from '../artifacts/contracts/zkdvrf.sol/zkdvrf.json'

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

export interface GasPriceOverride {
    gasLimit: number
    gasPrice?: number
}

interface NodeZkRandOptions {
    l2RpcProvider: providers.StaticJsonRpcProvider
    l2Wallet: Wallet
    // chain ID of the L2 network
    chainId: number
    zkRandAddress: string
    pollingInterval: number
}

const optionSettings = {}

export class NodeZkRandService extends BaseService<NodeZkRandOptions> {
    constructor(options: NodeZkRandOptions) {
        super('NodeZkRandService', options, optionSettings)
    }

    private state: {
        zkRandContract: Contract
        gasOverride: GasPriceOverride
    } = {} as any

    async _init(): Promise<void> {
        this.logger.info('Initializing NodeZkRand service...', {
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

    }

    async _start(): Promise<void> {
        console.log('---------------- node started ----------------')
        const threshold = await this.state.zkRandContract.threshold()

        while (this.running) {
            let contractPhase = await this.state.zkRandContract.contractPhase()
            console.log("contractPhase", contractPhase)
            let addrToNode = await this.state.zkRandContract.addrToNode(this.options.l2Wallet.address)

            // node address has been added by the admin
            if (addrToNode.nodeAddress == this.options.l2Wallet.address) {
                if (contractPhase == Status.Unregistered) {
                    // this indicates the address was not registered yet
                    if (!addrToNode.status) {
                        await this.registerNode()
                    }
                } else if (contractPhase == Status.Nidkg) {
                    // this indicates the address hasn't submitted public params
                    if (!addrToNode.statusPP) {
                        // submit public params
                        await this.submitPP()
                    }
                } else if (contractPhase == Status.Ready) {
                    let currentRound = await this.state.zkRandContract.currentRoundNum()
                    console.log("currentRound", currentRound.toString())
                    let roundSubmissionCount = await this.state.zkRandContract.roundSubmissionCount(currentRound)
                    console.log("roundSubmissionCount", roundSubmissionCount.toString())
                    let lastRoundSubmitted = await this.state.zkRandContract.lastSubmittedRound(this.options.l2Wallet.address)
                    console.log("lastRoundSubmitted", lastRoundSubmitted.toString())

                    // if there are already threshold number of submissions, then this node skips submission
                    if (currentRound > lastRoundSubmitted && roundSubmissionCount < threshold) {
                        if (lastRoundSubmitted == 0) {
                            await this.nidkgDerive()
                        }
                        await this.submitPartialEval()
                    }
                }
            }

            await sleep(this.options.pollingInterval)
        }
    }

    async registerNode() {
        // generate member secret key and member public key on grumpkin curve
        const index = this.options.l2Wallet.address
        const file = `member_${index}`
        const command = `RUST_LOG=info ./target/release/client keygen -f ${file}`

        console.log("running command <", command, ">...")
        const result = await execPromise(command);
        console.log(result[`stderr`]);

        // files need to exist at this location
        const filePath = memberDir + file + ".json"
        const data = readJsonFromFile(filePath);
        const mpk = data[`pk`]

        const res = await this.state.zkRandContract.registerNode(mpk)
        console.log("transaction hash for registerNode", res.hash)
        await res.wait()
        console.log("member ", index, "registered\n")
    }

    async listenRegister() {
        const eventName = `RegistrationCompleted`
        this.state.zkRandContract.on(eventName, async (count, event) => {
            console.log("event", eventName, count);
            // Proceed to the next step here
            const res = await this.state.zkRandContract.getPkList()
            console.log("downloaded all member public keys from contract")

            const pks = res.map(pk => ({x: pk[0].toHexString(), y: pk[1].toHexString()}))
            const obj = JSON.stringify(pks);
            await waitForWriteJsonToFile(obj, mpksPath);
        });
    }

    async listenNidkg() {
        const eventName = `NidkgCompleted`
        this.state.zkRandContract.on(eventName, async (count, event) => {
            console.log("\nevent", eventName, count)

            // read all instances from contract
            const ppList = await this.state.zkRandContract.getPpList()
            // save ppList for rust backend
            const ppListHex = ppList.map(subList =>
                subList.map(num => num.toHexString())
            );
            const obj = JSON.stringify(ppListHex)
            await waitForWriteJsonToFile(obj, instancesPath)
            console.log("sleeping..")
            await sleep(1000)

            // each member derives its own secret share and global public parameters
            const cmd = `RUST_LOG=info ./target/release/client dkg derive`
            const index = await this.state.zkRandContract.getIndexPlus(this.options.l2Wallet.address)
            const cmdMember = cmd + ` ${index} -f member_${this.options.l2Wallet.address}`
            console.log("running command <", cmdMember, ">...")
            const res = await execPromise(cmdMember)
            console.log(res[`stderr`])
        });
    }

    async submitPP() {
        const res = await this.state.zkRandContract.getPkList()
        console.log("downloaded all member public keys from contract")
        const pks = res.map(pk => ({x: pk[0].toHexString(), y: pk[1].toHexString()}))
        const obj = JSON.stringify(pks);
        await waitForWriteJsonToFile(obj, mpksPath);
        console.log("sleeping..")
        await sleep(1000)

        const index = await this.state.zkRandContract.getIndexPlus(this.options.l2Wallet.address)
        const cmdProve = `RUST_LOG=info ./target/release/client dkg prove ${index}`
        const cmdVerify = `RUST_LOG=info ./target/release/client dkg verify ${index}`

        // generate snark proof and instance
        console.log("running command <", cmdProve, ">...")
        let result = await execPromise(cmdProve)
        console.log(result[`stdout`])

        // verify snark proof and instance
        console.log("running command <", cmdVerify, ">...")
        result = await execPromise(cmdVerify)
        console.log(result[`stdout`])

        // read snark proof and instance
        const proofPath = dkgDir + `proofs/proof_${index}.dat`
        const instancePath = dkgDir + `proofs/instance_${index}.json`

        const proof = readBytesFromFile(proofPath)
        const instance = readJsonFromFile(instancePath)

        // submit proof and instance to contract
        const resPP = await this.state.zkRandContract.submitPublicParams(instance, proof)
        console.log("transaction hash for submitPublicParams:", resPP.hash)
        resPP.wait()
    }

    async nidkgDerive() {
        // read all instances from contract
        const ppList = await this.state.zkRandContract.getPpList()
        // save ppList for rust backend
        const ppListHex = ppList.map(subList =>
            subList.map(num => num.toHexString())
        );
        const obj = JSON.stringify(ppListHex)
        await waitForWriteJsonToFile(obj, instancesPath)
        console.log("sleeping..")
        await sleep(2000)

        // each member derives its own secret share and global public parameters
        const cmd = `RUST_LOG=info ./target/release/client dkg derive`
        const index = await this.state.zkRandContract.getIndexPlus(this.options.l2Wallet.address)
        const cmdMember = cmd + ` ${index} -f member_${this.options.l2Wallet.address}`
        console.log("running command <", cmdMember, ">...")
        const res = await execPromise(cmdMember)
        console.log(res[`stderr`])
    }

    async submitPartialEval() {
        const currentRound = await this.state.zkRandContract.currentRoundNum()
        const input = await this.state.zkRandContract.roundInput(currentRound)
        const index = await this.state.zkRandContract.getIndexPlus(this.options.l2Wallet.address)

        const cmdEval = `RUST_LOG=info ./target/release/client rand eval ${index} "${input}"`
        const cmdVerify = `RUST_LOG=info ./target/release/client rand verify ${index} "${input}"`

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

        const res = await this.state.zkRandContract.submitPartialEval(pEval)
        console.log("transaction hash for submitPartialEval", res.hash)
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

export function readBytesFromFile(filePath: string): Uint8Array | null {
    try {
        // Read the file synchronously
        const fileData: Buffer = fs.readFileSync(filePath);

        // Access the bytes of the file
        const bytes: Uint8Array = new Uint8Array(fileData);

        return bytes;
    } catch (err) {
        console.error('Error reading file:', err);
        return null;
    }
}