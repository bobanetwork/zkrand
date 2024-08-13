import hre, {artifacts, ethers} from "hardhat";
import {providers, Wallet} from "ethers";
import {readJsonFromFile} from "../utils";

const config = readJsonFromFile("demo-config.json")
const rpcUrl = config.rpcUrl
const lotteryAddress = config.lotteryAddress
const playerKeys = config.lotteryPlayerKeys


async function main() {
    const netprovider = new providers.JsonRpcProvider(rpcUrl)

    const Lottery = await ethers.getContractFactory('Lottery')
    const contractABI = Lottery.interface.format();
    const contract = new ethers.Contract(lotteryAddress, contractABI, netprovider);

    // This will run when the event is emitted
    const eventName = `BetOpen`
    contract.on(eventName, async (randRoundNum, minBet, event) => {
        console.log("event", eventName, randRoundNum, minBet);
        // Proceed to the next step here

        for (let i = 0; i < playerKeys.length; i++) {
            const userWallet = new Wallet(playerKeys[i], netprovider)
            const userAddress = userWallet.address
            const userContract = contract.connect(userWallet)

            try {
                let tx = await userContract.enter({
                    value: minBet,
                    from: userAddress,
                });
                await tx.wait()
                console.log("player", userAddress, "placed bet", minBet);
            } catch (err) {
                console.error(err);
            }
        }

        process.exit(0);
    });
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});