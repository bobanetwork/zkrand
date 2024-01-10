// SPDX-License-Identifier: MIT

// solc --via-ir GlobalPublicParams.sol --bin --abi --optimize --overwrite -o build/

pragma solidity ^0.8.0;

import {Pairing} from "./libs/Pairing.sol";

contract GlobalPublicParams {
    // parameters from zkdvrf
    uint32 internal constant NUMBER_OF_LIMBS = 4;
    uint32 internal constant BIT_LEN_LIMB = 68;
    uint32 internal constant WRAP_LEN = 2;
    uint32 internal constant COORD_LEN = NUMBER_OF_LIMBS / WRAP_LEN;
    uint32 internal constant POINT_LEN = COORD_LEN * 2;
    uint internal constant BASE = 1 << (BIT_LEN_LIMB * WRAP_LEN);

    using Pairing for *;

    function readBnG1(uint[] memory g) internal pure returns (Pairing.G1Point memory) {
        assert(g.length == POINT_LEN);

        // unwrap G1 points
        uint x = g[COORD_LEN-1];
        for (uint i = COORD_LEN-1; i > 0; i--) {
            x = x * BASE + g[i-1];
        }

        uint y = g[g.length-1];
        for (uint i = g.length-1; i > COORD_LEN; i--) {
            y = y * BASE + g[i-1];
        }

        return Pairing.G1Point(x,y);
    }


    function createGpp(
        uint32 numOfMembers,
        Pairing.G2Point calldata gpk,
        // instances from n members that have been verified
        uint[][] calldata validInstances
    ) public returns (Pairing.G2Point memory, Pairing.G1Point[] memory) {
        assert(BIT_LEN_LIMB < 128);
        assert(BIT_LEN_LIMB * WRAP_LEN < 254);
        assert(NUMBER_OF_LIMBS % WRAP_LEN == 0);

        require(validInstances.length <= numOfMembers, "too many instances");

        // each instance needs to have 4n+4 elements
        {
            uint32 sizeInstance = 4 * numOfMembers + 4;
            for (uint i = 0; i < validInstances.length; i++) {
                require(validInstances[i].length >= sizeInstance, "not enough elements");
            }
        }

        // compute ga
        Pairing.G1Point memory ga = Pairing.G1Point(0, 0);
        {
            // ga = ga_1 + ... + ga_k
            for (uint32 i = 0; i < validInstances.length; i++) {
                // read bn point g^a
                Pairing.G1Point memory ga_i = readBnG1(validInstances[i][0:POINT_LEN]);
                ga = Pairing.addition(ga, ga_i);
            }
        }

        // compute vk_1, ..., vk_n
        Pairing.G1Point[] memory vk_vec = new Pairing.G1Point[](numOfMembers);
        {
            // gs_{1,1}...gs_{1,n}
            // ...
            // gs_{k,1}...gs_{k,n}
            // vk_j = gs_{1, j} + ... gs_{k, j}
            uint32 begin = POINT_LEN;
            uint32 end = begin + POINT_LEN;

             for (uint32 j = 0; j < numOfMembers; j++) {
                // begin =  POINT_LEN * (j+1);
                // end = begin + POINT_LEN;
                 vk_vec[j] = Pairing.G1Point(0, 0);
                 for (uint32 i = 0; i < validInstances.length; i++) {
                    Pairing.G1Point memory gs_ij = readBnG1(validInstances[i][begin:end]);
                    vk_vec[j] = Pairing.addition(vk_vec[j], gs_ij);
                 }

                 begin = end;
                 end = begin + POINT_LEN;
             }
        }

        // check validity of gpk: e(ga, g2)e(-g, gpk) = 1
        {
            bool succeed = Pairing.pairingProd2(ga, Pairing.P2(), Pairing.P1().negate(), gpk);
            require(succeed, "invalid gpk");
        }

        return (gpk, vk_vec);
    }
}