// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Pairing} from "./libs/Pairing.sol";

interface IPseudoRand {

    struct PartialEvalProof {
        uint z;
        uint c;
    }

    struct PartialEval {
        uint32 index;
        Pairing.G1Point value;
        IPseudoRand.PartialEvalProof proof;
    }

    struct PseudoRandom {
        Pairing.G1Point proof;
        bytes32 value;
    }

    function verifyPartialEvalFast(
        Pairing.G1Point memory h,
        Pairing.G1Point memory sigma,
        PartialEvalProof memory proof,
        Pairing.G1Point memory vk
    ) external returns (bool);

    function verifyPartialEval(
        bytes memory message,
        Pairing.G1Point memory sigma,
        PartialEvalProof memory proof,
        Pairing.G1Point memory vk
    ) external returns (bool);

    function verifyPseudoRandFast(
        Pairing.G1Point memory h,
        Pairing.G1Point memory sigma,
        Pairing.G2Point memory gpk
    ) external returns (bool);

    function verifyPseudoRand(
        bytes memory message,
        Pairing.G1Point memory sigma,
        Pairing.G2Point memory gpk
    ) external returns (bool);

}