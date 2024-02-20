// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Halo2Verifier} from "./Halo2Verifier-3-5-g2.sol";
import {GlobalPublicParams} from "./GlobalPublicParams.sol";
import {Pairing} from "./libs/Pairing.sol";
import {IPseudoRand} from "./IPseudoRand.sol";

import "@openzeppelin/contracts/utils/Strings.sol";
import '@openzeppelin/contracts/access/Ownable.sol';

contract zkdvrf is Ownable {
    using Strings for uint256;

    struct dvrfNode {
        uint32 index;
        address nodeAddress;
        bool status;
        uint256 deposit;
        bool statusPP;
    }

    enum Status {
        Unregistered,
        Nidkg,
        NidkgComplete,
        Ready
    }

    uint32 public memberCount;
    uint32 public threshold;
    uint32 internal currentIndex;
    uint32 internal registeredCount;

    uint256 public currentRoundNum;

    uint256[][] public ppList;
    // vk list order is also same
    uint32 public ppListIndex;
    address[] public ppListOrder;
    Pairing.G1Point[] public vkList;
    Pairing.G2Point internal gpkVal;

    Status public contractPhase;
    address public halo2Verifier;
    address public globalPublicParams;
    address public pseudoRand;


    mapping (uint32 => dvrfNode) public indexToNode;
    mapping (address => dvrfNode) public addrToNode;
    mapping (address => uint32) public ppListOrderMap;
    mapping (uint256 => string) public roundInput;
    mapping (address => uint256) public lastSubmittedRound;
    // can convert these below two to a struct
    mapping (uint256 => mapping (uint32 => Pairing.G1Point)) public roundToEval;
    mapping (uint256 => uint32) public roundSubmissionCount;
    mapping (uint256 => bytes) public roundToRandom;

    constructor(address halo2VerifierAddress, address globalPublicParamsAddress, address pseudoRandAddress) Ownable(msg.sender) {
        require (halo2VerifierAddress != address(0) && globalPublicParamsAddress != address(0) && pseudoRandAddress != address(0), "Cannot be zero addresses");
        memberCount = 5;
        threshold = 3;
        halo2Verifier = halo2VerifierAddress;
        globalPublicParams = globalPublicParamsAddress;
        pseudoRand = pseudoRandAddress;
    }

    // add Nodes to contract (permissioned) added by contract owner
    // check each method can only be called in a certain phase
    function addPermissionedNodes(address nodeAddress) public onlyOwner {
        require(currentIndex < memberCount, "All members added");
        indexToNode[currentIndex] = dvrfNode(currentIndex, nodeAddress, false, 0, false);
        addrToNode[nodeAddress] = dvrfNode(currentIndex, nodeAddress, false, 0, false);
        currentIndex++;
    }

    // each node register with deposit and confirms
    function registerNode() public payable {
        require(msg.sender == addrToNode[msg.sender].nodeAddress, "Unauthorized call");
        require(!addrToNode[msg.sender].status, "Node Already registered");
        uint32 indexFetched = addrToNode[msg.sender].index;
        indexToNode[indexFetched].deposit = msg.value;
        indexToNode[indexFetched].status = true;
        addrToNode[msg.sender].deposit = msg.value;
        addrToNode[msg.sender].status = true;
        registeredCount++;
    }

    // owner Start Phase 1 (needs enum stating status of contracts)
    function startNidkg() public onlyOwner {
        // can't add nodes after this process
        require(registeredCount == memberCount, "Not all Members are ready");
        contractPhase = Status.Nidkg;
    }

    // each node can submit pp_i, zk_i
    // contract validates zk_i here for each submission and then accepts it
    function submitPublicParams(uint256[] calldata pp, bytes calldata zkProof) public {
        require(contractPhase == Status.Nidkg, "Contract not in NIDKG phase");
        require(!addrToNode[msg.sender].statusPP, "Node already submitted");
        require(Halo2Verifier(halo2Verifier).verifyProof(zkProof, pp));
        uint32 indexFetched = addrToNode[msg.sender].index;
        indexToNode[indexFetched].statusPP = true;
        addrToNode[msg.sender].statusPP = true;

        ppList.push(pp);
        // make this a queue method
        ppListOrderMap[msg.sender] = ppListIndex;
        ppListIndex++;
        ppListOrder.push(msg.sender);
        // add addresses index on this pp list
        // will only happen when all public params are submitted
        if (ppList.length == memberCount) {
            contractPhase = Status.NidkgComplete;
        }
    }

    // compute gpk and vk and store on the contract, can be done by the owner
    // anyone can call
    function computeVk(Pairing.G2Point calldata gpk) public {
        require(contractPhase == Status.NidkgComplete, "Partial Parameter submission not complete");
        (Pairing.G2Point memory gpkRet, Pairing.G1Point[] memory vk) = GlobalPublicParams(globalPublicParams).createGpp(memberCount, gpk, ppList);
        for (uint i = 0; i < vk.length; i++) {
            vkList.push(vk[i]);
        }
        gpkVal = gpkRet;
        contractPhase = Status.Ready;
    }

    // 2nd Phase

    // can take an optional input
    function generateRandom() public onlyOwner {
        require(contractPhase == Status.Ready, "Contract not ready");
        if (currentRoundNum != 0) {
            require(roundToRandom[currentRoundNum - 1].length != 0, "Earlier round not completed");
        }
        // check last round completed
        currentRoundNum++;
        uint256 currentTimestamp = block.timestamp;
        roundInput[currentRoundNum] = currentTimestamp.toString();
    }

    // // use Concat string utils to use xInput + block.timestamp
    // function generateRandom(string memory xInput) public {
    //     // check last round completed
    //     currentRoundNum++;
    //     roundInput[currentRoundNum] = xInput;
    // }

    function submitPartialEval(Pairing.G1Point memory pEval, IPseudoRand.PartialEvalProof memory proof) public {
        // check valid round
        require(roundToRandom[currentRoundNum].length == 0, "Round already computed");
        require (lastSubmittedRound[msg.sender] < currentRoundNum, "Already submitted for round");
        bytes memory currentX = bytes(roundInput[currentRoundNum]);
        uint32 ppIndex = ppListOrderMap[msg.sender];
        Pairing.G1Point memory vkStored = vkList[ppIndex];
        require(IPseudoRand(pseudoRand).verifyPartialEval(currentX, pEval, proof, vkStored), "Verification of partial eval failed");
        lastSubmittedRound[msg.sender] = currentRoundNum;
        roundToEval[currentRoundNum][ppIndex] = pEval;
        roundSubmissionCount[currentRoundNum]++;
    }

    // accept a set of partial evals
    // take sigma as a param, basically a point that the operator submits (combination of subset of partial evals)
    // take the pseudorandom result, which is the bytes memory message
    // take the gpk as stored in contract
    function generateRandom(Pairing.G1Point memory sigma, bytes memory random) public onlyOwner{
        require(roundToRandom[currentRoundNum].length == 0, "Answer for round already exists");
        require(roundSubmissionCount[currentRoundNum] >= threshold, "Partial evaluation threshold not reached");
        require(IPseudoRand(pseudoRand).verifyPseudoRand(random, sigma, gpkVal), "Incorrect random submitted");
        roundToRandom[currentRoundNum] = random;
    }
}