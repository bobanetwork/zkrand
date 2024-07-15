// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Halo2Verifier} from "./Halo2Verifier.sol";
import {GlobalPublicParams} from "./GlobalPublicParams.sol";
import {Pairing} from "./libs/Pairing.sol";
import {IPseudoRand} from "./IPseudoRand.sol";
import {Grumpkin} from "./libs/Grumpkin.sol";

import "@openzeppelin/contracts/utils/Strings.sol";
import '@openzeppelin/contracts/access/Ownable.sol';

// zkdvrf with precomputation for hash2curve
contract zkdvrf_pre is Ownable {
    using Strings for uint256;
    using Grumpkin for *;

    event RegistrationCompleted(uint32 count);
    event NidkgStarted();
    event NidkgCompleted(uint32 count);
    event GlobalPublicParamsCreated();
    event RandomInitiated(uint roundNum, string input);
    event RandomThresholdReached(uint roundNum, string input);
    event RandomReady(uint roundNum, string input);

    struct dvrfNode {
        address nodeAddress;
        bool status;
        uint256 deposit;
        bool statusPP;
        uint32 pkIndex;
    }

    enum Status {
        Unregistered,
        Registered,
        Nidkg,
        NidkgComplete,
        Ready
    }

    string public constant INPUT_PREFIX = "zkRand-v1-2024:";

    uint32 public memberCount;
    uint32 public threshold;
    uint32 public ppLength;
    // current count of members added
    uint32 public currentIndex;
    // current count of members deposited and registered
    uint32 internal registeredCount;
    uint32 internal ppSubmissionCount;

    uint256 public currentRoundNum;
    uint256 public minNodeDeposit;

    uint32 public pkListIndex;
    Grumpkin.Point[] public pkList;

    uint256[][] public ppList;

    // The order in vkList is the same as pkList
    Pairing.G1Point[] public vkList;
    Pairing.G2Point internal gpkVal;

    Status public contractPhase;
    address public halo2Verifier;
    address public halo2VerifyingKey;
    address public globalPublicParams;
    address public pseudoRand;

    mapping(uint32 => address) public nodes;
    mapping(address => dvrfNode) public addrToNode;
    mapping(uint256 => string) public roundInput;
    mapping(uint256 => Pairing.G1Point) public roundHash;
    mapping(address => uint256) public lastSubmittedRound;
    mapping(uint256 => mapping(uint32 => IPseudoRand.PartialEval)) public roundToEval;
    mapping(uint256 => uint32) public roundSubmissionCount;
    mapping(uint256 => IPseudoRand.PseudoRandom) public roundToRandom;


    constructor(uint32 thresholdValue, uint32 numberValue, address halo2VerifierAddress, address halo2VerifyingKeyAddress, address globalPublicParamsAddress, address pseudoRandAddress, uint256 minDeposit) Ownable(msg.sender) {
        require(halo2VerifierAddress != address(0) && globalPublicParamsAddress != address(0) && pseudoRandAddress != address(0), "Cannot be zero addresses");
        memberCount = numberValue;
        threshold = thresholdValue;
        ppLength = 7 * memberCount + 14;
        halo2Verifier = halo2VerifierAddress;
        halo2VerifyingKey = halo2VerifyingKeyAddress;
        globalPublicParams = globalPublicParamsAddress;
        pseudoRand = pseudoRandAddress;
        minNodeDeposit = minDeposit;
    }

    // works until all members added,
    // to move to the next phase registeredCount has to be equal to memberCount
    function addPermissionedNodes(address nodeAddress) public onlyOwner {
        require(currentIndex < memberCount, "All members added");
        require(nodeAddress != address(0), "Node cannot be zero address");
        require(addrToNode[nodeAddress].nodeAddress == address(0), "Node has already been added");

        addrToNode[nodeAddress] = dvrfNode(nodeAddress, false, 0, false, 0);
        currentIndex++;
    }

    // each member registers with deposit and confirms
    function registerNode(Grumpkin.Point memory pubKey) public payable {
        require(contractPhase == Status.Unregistered, "Registration has already been completed");
        require(msg.sender == addrToNode[msg.sender].nodeAddress, "Unauthorized call");
        require(!addrToNode[msg.sender].status, "Node Already registered");
        require(msg.value >= minNodeDeposit, "Must provide enough node deposit");
        require(Grumpkin.isOnCurve(pubKey), "Invalid Public Key submitted");

        nodes[registeredCount] = msg.sender;
        addrToNode[msg.sender].deposit = msg.value;
        addrToNode[msg.sender].status = true;
        addrToNode[msg.sender].pkIndex = pkListIndex;
        pkList.push(pubKey);
        pkListIndex++;
        registeredCount++;

        // all the permitted nodes have registered
        if (registeredCount == memberCount) {
            contractPhase = Status.Registered;
            emit RegistrationCompleted(registeredCount);
        }
    }

    // owner starts nidkg protocol
    // can't add members after this process
    function startNidkg() public onlyOwner {
        require(contractPhase == Status.Registered, "Cannot start NIDKG");
        contractPhase = Status.Nidkg;

        emit NidkgStarted();
    }

    // each member can submit pp_i, zk_i
    // contract validates zk_i here for each submission and then accepts it
    function submitPublicParams(uint256[] calldata pp, bytes calldata zkProof) public {
        require(msg.sender == addrToNode[msg.sender].nodeAddress, "Unauthorized call");
        require(contractPhase == Status.Nidkg, "Contract not in NIDKG phase");
        require(!addrToNode[msg.sender].statusPP, "Node already submitted");
        require(checkPublicParams(pp), "Invalid public parameters");
        require(Halo2Verifier(halo2Verifier).verifyProof(halo2VerifyingKey, zkProof, pp), "SNARK proof verification failed");

        addrToNode[msg.sender].statusPP = true;
        ppList.push(pp);
        ppSubmissionCount++;

        if (ppSubmissionCount == memberCount) {
            contractPhase = Status.NidkgComplete;
            emit NidkgCompleted(ppSubmissionCount);
        }
    }

    // compute gpk and vk and store on the contract
    function computeVk(Pairing.G2Point calldata gpk) public {
        require(contractPhase == Status.NidkgComplete, "Partial Parameter submission not complete");
        (Pairing.G2Point memory gpkRet, Pairing.G1Point[] memory vk) = GlobalPublicParams(globalPublicParams).createGpp(memberCount, gpk, ppList);
        for (uint i = 0; i < vk.length; i++) {
            vkList.push(vk[i]);
        }
        gpkVal = gpkRet;
        contractPhase = Status.Ready;

        emit GlobalPublicParamsCreated();
    }

    // initiate public inputs for generating randoms
    function initiateRandom() public onlyOwner {
        require(contractPhase == Status.Ready, "Contract not ready");

        if (currentRoundNum != 0) {
            require(roundToRandom[currentRoundNum].value != bytes32(0), "Earlier round not completed");
        }

        currentRoundNum++;
        bytes memory input = abi.encodePacked(INPUT_PREFIX, currentRoundNum.toString());
        roundInput[currentRoundNum] = string(input);
        roundHash[currentRoundNum] = IPseudoRand(pseudoRand).hashToG1(input);

        emit RandomInitiated(currentRoundNum, roundInput[currentRoundNum]);
    }

    // each member can submit their partial evaluation.
    // this function can be taken offchain. The onchain storage and verification can help determine which node to reward or punish.
    function submitPartialEval(IPseudoRand.PartialEval memory pEval) public {
        require(msg.sender == addrToNode[msg.sender].nodeAddress, "Unauthorized call");
        // check valid round
        require(roundToRandom[currentRoundNum].value == bytes32(0), "Round already computed");
        // this will help revert calls if the contract status is not Ready and the first initiateRandom() is not called
        require(lastSubmittedRound[msg.sender] < currentRoundNum, "Already submitted for round");
        uint32 pkIndex = addrToNode[msg.sender].pkIndex;
        require(pEval.indexPlus == pkIndex + 1);
        Pairing.G1Point memory vkStored = vkList[pkIndex];
        require(IPseudoRand(pseudoRand).verifyPartialEvalFast(roundHash[currentRoundNum], pEval.value, pEval.proof, vkStored), "Verification of partial eval failed");
        lastSubmittedRound[msg.sender] = currentRoundNum;
        roundToEval[currentRoundNum][pkIndex] = pEval;
        roundSubmissionCount[currentRoundNum]++;

        if (roundSubmissionCount[currentRoundNum] == threshold) {
            emit RandomThresholdReached(currentRoundNum, roundInput[currentRoundNum]);
        }
    }

    // submit the final pseudorandom value which is computed by combining t partial evaluations offchain
    function submitRandom(IPseudoRand.PseudoRandom memory pseudo) public onlyOwner {
        require(roundToRandom[currentRoundNum].value == bytes32(0), "Answer for round already exists");
        require(roundSubmissionCount[currentRoundNum] >= threshold, "Partial evaluation threshold not reached");
        require(IPseudoRand(pseudoRand).verifyPseudoRandFast(roundHash[currentRoundNum], pseudo.proof, gpkVal), "Incorrect random submitted");
        bytes32 value = keccak256(abi.encodePacked(pseudo.proof.x, pseudo.proof.y));
        require(pseudo.value == value, "Incorrect pseudorandom value");
        roundToRandom[currentRoundNum] = pseudo;

        emit RandomReady(currentRoundNum, roundInput[currentRoundNum]);
    }

    function getLatestRandom() public view returns (IPseudoRand.PseudoRandom memory pseudo) {
        if (roundToRandom[currentRoundNum].value != bytes32(0)) {
            return roundToRandom[currentRoundNum];
        }

        if (currentRoundNum == 1) {
            revert("Answer does not exist for the round yet");
        }

        return roundToRandom[currentRoundNum - 1];
    }

    function getRandomAtRound(uint256 roundNum) public view returns (IPseudoRand.PseudoRandom memory pseudo) {
        if (roundToRandom[roundNum].value != bytes32(0)) {
            return roundToRandom[roundNum];
        }

        revert("Answer does not exist for the round yet");
    }

    function checkPublicParams(uint256[] calldata pp) public view returns (bool) {
        require(pkList.length == memberCount, "Not enough member public keys");

        require(pp.length == ppLength, "Wrong size of public parameters");
        if (pp.length != ppLength) {
            return false;
        }

        // check if the last 2n elements in pp are public keys
        uint j = pp.length - 2 * memberCount;
        for (uint i = 0; i < memberCount; i++) {
            require(pp[j] == pkList[i].x, "Wrong public key x");
            require(pp[j + 1] == pkList[i].y, "Wrong public key y");
            if (pp[j] != pkList[i].x || pp[j + 1] != pkList[i].y) {
                return false;
            }
            j = j + 2;
        }

        return true;
    }

    function getIndexPlus(address nodeAdress) public view returns (uint32) {
        uint32 pkIndex = addrToNode[nodeAdress].pkIndex;
        return pkIndex + 1;
    }

    function getPkList() public view returns (Grumpkin.Point[] memory) {
        return pkList;
    }

    function getPpList() public view returns (uint256[][] memory) {
        return ppList;
    }

    function getGpk() public view returns (Pairing.G2Point memory) {
        return gpkVal;
    }

    function getVkList() public view returns (Pairing.G1Point[] memory) {
        return vkList;
    }
}