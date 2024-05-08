// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {zkdvrf} from "./zkdvrf.sol";

import "@openzeppelin/contracts/utils/Strings.sol";
import '@openzeppelin/contracts/access/Ownable.sol';

contract Lottery is Ownable {
    using Strings for uint256;

    address payable[] public players;
    uint256 public minBet;

    address public zkdvrfAddr;
    uint256 public randRoundNum;
    bytes32 public randValue;

    enum Status {
        Setup,
        Open,
        Close
    }

    Status public contractPhase;

    event BetOpen(uint256 randRoundNumber, uint256 minBetAmount);

    constructor(address zkdvrfAddress) Ownable(msg.sender) {
        zkdvrfAddr = zkdvrfAddress;
    }

    function setup(uint256 randRoundNumber, uint256 minBetAmount) public onlyOwner {
        require(contractPhase == Status.Setup, "Setup has already been completed");
        randRoundNum = randRoundNumber;
        minBet = minBetAmount;

        contractPhase = Status.Open;
        emit BetOpen(randRoundNumber, minBetAmount);
    }

    // check if random has been produced or is being produced
    function roundReached() public returns (bool) {
        uint256 latestRoundNum = zkdvrf(zkdvrfAddr).currentRoundNum();
        return randRoundNum <= latestRoundNum;
    }

    function enter() public payable {
        require(contractPhase == Status.Open, "Not open yet");
        // Once the random generation starts or has completed, players are no longer allowed to enter
        require(!roundReached(), "Too late. Random has been produced or is being produced");
        require(msg.value >= minBet, "Must provide enough bet");

        players.push(payable(msg.sender));
    }

    // Fisher-Yates Shuffle
    function shuffle() private {
        require(randValue != 0x00, "Random not ready yet");

        for (uint i = 0; i < players.length; i++) {
            bytes32 randomBytes = keccak256(abi.encodePacked(randValue, i));
            uint256 random = uint256(randomBytes);

            uint j = random % (i + 1);
            (players[i], players[j]) = (players[j], players[i]);
        }
    }

    function pickWinner() public onlyOwner {
        require(players.length > 0, "No players");
        // read random from zkdvrf contract
        randValue = zkdvrf(zkdvrfAddr).getRandomAtRound(randRoundNum).value;
        shuffle(); // Shuffle the players array
        // The winner is the first player in the shuffled array
        // The permutation is randomly generated so we can also take more winners if needed
        players[0].transfer(address(this).balance);
      //  players = new address payable; // Resetting the players array

        contractPhase = Status.Close;
    }


    function getPlayers() public view returns (address payable[] memory) {
        return players;
    }
}
