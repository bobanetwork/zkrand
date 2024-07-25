import hre, {artifacts, ethers} from "hardhat";
import {Contract, ContractFactory, providers, utils, Wallet} from "ethers";
import {readJsonFromFile} from "../utils";

const config = readJsonFromFile("demo-config.json")
const rpcUrl = config.rpcUrl
const zkdvrfAddress = config.zkdvrfAddress
const lotteryAddress = config.lotteryAddress
const adminKey = config.lotteryAdminKey

async function main() {
    const netprovider = new providers.JsonRpcProvider(rpcUrl)
    const adminWallet = new Wallet(adminKey, netprovider)

    const Lottery = await ethers.getContractFactory('Lottery')
    const contractABI = Lottery.interface.format();
    const contract = new ethers.Contract(lotteryAddress, contractABI, netprovider).connect(adminWallet)

    const randRoundNumber = 3
    const minBet = ethers.utils.parseEther("5");
    const res = await contract.setup(randRoundNumber, minBet)
    const receipt = await netprovider.getTransactionReceipt(res.hash);
    // Check if the transaction was successful
    if (receipt.status === 1) {
        console.log(`Transaction setup(..) successful!`);
    } else {
        console.error(`Transaction setup(..) failed!`);
    }
    console.log("Bet starts")
    console.log("Waiting for random in round ", randRoundNumber)

    const Zkdvrf = await ethers.getContractFactory('zkdvrf')
    const zkContractABI = Zkdvrf.interface.format();
    const zkContract = new ethers.Contract(zkdvrfAddress, zkContractABI, netprovider)

    // This will run when the event is emitted
    const eventName = `RandomReady`
    zkContract.on(eventName, async (roundNum, input, event) => {
        console.log("event", eventName, roundNum, input);
        // Proceed to the next step here
        if (roundNum == randRoundNumber) {
            const playersBefore = await contract.getPlayers()
            console.log("Players before:", playersBefore)
            // the random number is ready
            const res = await contract.pickWinner()
            // Check if the transaction was successful
            const receipt = await netprovider.getTransactionReceipt(res.hash);
            if (receipt.status === 1) {
                console.log("Transaction pickWinner() successful!");
            } else {
                console.error("Transaction pickWinner() failed!");
            }

            const status = await contract.contractPhase()
            console.log("Lottery contract status:", status)

            const players = await contract.getPlayers()
            console.log("Players after:", players)

            // query users balance
            for (let i = 0; i < players.length; i++) {
                netprovider.getBalance(players[i]).then((balance) => {
                    // Convert Wei to Ether
                    let etherString = ethers.utils.formatEther(balance);
                    console.log(players[i], " balance: " + etherString);
                }).catch((err) => {
                    console.error(err);
                });
            }
        }
    });

}


main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
