// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Pairing} from "./libs/Pairing.sol";
import {Hash} from "./libs/Hash.sol";
import {IPseudoRand} from "./IPseudoRand.sol";

contract PseudoRand is IPseudoRand{
    using Pairing for *;
    using Hash for *;

    bytes public constant DOMAIN = bytes("DVRF pseudorandom generation 2023");
    uint public constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // verify partial eval without computing hash to point
    function verifyPartialEvalFast(
        Pairing.G1Point memory h,
        Pairing.G1Point memory sigma,
        PartialEvalProof memory proof,
        Pairing.G1Point memory vk
    ) public view returns (bool)  {
        Pairing.G1Point memory g = Pairing.P1();

        Pairing.G1Point memory gz = Pairing.scalar_mul(g, proof.z);
        Pairing.G1Point memory vkc = Pairing.scalar_mul(vk, proof.c);
        Pairing.G1Point memory r1 = Pairing.addition(gz, vkc.negate());

        Pairing.G1Point memory hz = Pairing.scalar_mul(h, proof.z);
        Pairing.G1Point memory sc = Pairing.scalar_mul(sigma, proof.c);
        Pairing.G1Point memory r2 = Pairing.addition(hz, sc.negate());

        bytes memory input = abi.encodePacked(g.x, g.y, h.x, h.y, r1.x, r1.y,
            r2.x, r2.y,vk.x, vk.y, sigma.x, sigma.y);
        bytes32 hash = keccak256(input);

        uint cc = uint(hash) % R;
        return cc == proof.c;
    }

    function verifyPartialEval(
        bytes memory message,
        Pairing.G1Point memory sigma,
        PartialEvalProof memory proof,
        Pairing.G1Point memory vk
    ) public view returns (bool)  {
        Pairing.G1Point memory h = Hash.hashToG1(DOMAIN, message);
        Pairing.G1Point memory g = Pairing.P1();

        Pairing.G1Point memory gz = Pairing.scalar_mul(g, proof.z);
        Pairing.G1Point memory vkc = Pairing.scalar_mul(vk, proof.c);
        Pairing.G1Point memory r1 = Pairing.addition(gz, vkc.negate());

        Pairing.G1Point memory hz = Pairing.scalar_mul(h, proof.z);
        Pairing.G1Point memory sc = Pairing.scalar_mul(sigma, proof.c);
        Pairing.G1Point memory r2 = Pairing.addition(hz, sc.negate());

        bytes memory input = abi.encodePacked(g.x, g.y, h.x, h.y, r1.x, r1.y,
            r2.x, r2.y,vk.x, vk.y, sigma.x, sigma.y);
        bytes32 hash = keccak256(input);

        uint cc = uint(hash) % R;
        return cc == proof.c;
    }

    function verifyPseudoRandFast(Pairing.G1Point memory h, Pairing.G1Point memory sigma, Pairing.G2Point memory gpk) public view returns (bool) {
        Pairing.G1Point memory hn = h.negate();
        Pairing.G2Point memory g2 = Pairing.P2();

        return Pairing.pairingProd2(hn, gpk, sigma, g2);
    }

    function verifyPseudoRand(bytes memory message, Pairing.G1Point memory sigma, Pairing.G2Point memory gpk) public view returns (bool) {
        Pairing.G1Point memory h = Hash.hashToG1(DOMAIN, message);
        h = h.negate();
        Pairing.G2Point memory g2 = Pairing.P2();

        return Pairing.pairingProd2(h, gpk, sigma, g2);
    }
}