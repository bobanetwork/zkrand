// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2Verifier {
    uint256 internal constant    PROOF_LEN_CPTR = 0x44;
    uint256 internal constant        PROOF_CPTR = 0x64;
    uint256 internal constant NUM_INSTANCE_CPTR = 0x11e4;
    uint256 internal constant     INSTANCE_CPTR = 0x1204;

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x0664;
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = 0x0764;

    uint256 internal constant                VK_MPTR = 0x06c0;
    uint256 internal constant         VK_DIGEST_MPTR = 0x06c0;
    uint256 internal constant     NUM_INSTANCES_MPTR = 0x06e0;
    uint256 internal constant                 K_MPTR = 0x0700;
    uint256 internal constant             N_INV_MPTR = 0x0720;
    uint256 internal constant             OMEGA_MPTR = 0x0740;
    uint256 internal constant         OMEGA_INV_MPTR = 0x0760;
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = 0x0780;
    uint256 internal constant   HAS_ACCUMULATOR_MPTR = 0x07a0;
    uint256 internal constant        ACC_OFFSET_MPTR = 0x07c0;
    uint256 internal constant     NUM_ACC_LIMBS_MPTR = 0x07e0;
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = 0x0800;
    uint256 internal constant              G1_X_MPTR = 0x0820;
    uint256 internal constant              G1_Y_MPTR = 0x0840;
    uint256 internal constant            G2_X_1_MPTR = 0x0860;
    uint256 internal constant            G2_X_2_MPTR = 0x0880;
    uint256 internal constant            G2_Y_1_MPTR = 0x08a0;
    uint256 internal constant            G2_Y_2_MPTR = 0x08c0;
    uint256 internal constant      NEG_S_G2_X_1_MPTR = 0x08e0;
    uint256 internal constant      NEG_S_G2_X_2_MPTR = 0x0900;
    uint256 internal constant      NEG_S_G2_Y_1_MPTR = 0x0920;
    uint256 internal constant      NEG_S_G2_Y_2_MPTR = 0x0940;

    uint256 internal constant CHALLENGE_MPTR = 0x1160;

    uint256 internal constant THETA_MPTR = 0x1160;
    uint256 internal constant  BETA_MPTR = 0x1180;
    uint256 internal constant GAMMA_MPTR = 0x11a0;
    uint256 internal constant     Y_MPTR = 0x11c0;
    uint256 internal constant     X_MPTR = 0x11e0;
    uint256 internal constant  ZETA_MPTR = 0x1200;
    uint256 internal constant    NU_MPTR = 0x1220;
    uint256 internal constant    MU_MPTR = 0x1240;

    uint256 internal constant       ACC_LHS_X_MPTR = 0x1260;
    uint256 internal constant       ACC_LHS_Y_MPTR = 0x1280;
    uint256 internal constant       ACC_RHS_X_MPTR = 0x12a0;
    uint256 internal constant       ACC_RHS_Y_MPTR = 0x12c0;
    uint256 internal constant             X_N_MPTR = 0x12e0;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x1300;
    uint256 internal constant          L_LAST_MPTR = 0x1320;
    uint256 internal constant         L_BLIND_MPTR = 0x1340;
    uint256 internal constant             L_0_MPTR = 0x1360;
    uint256 internal constant   INSTANCE_EVAL_MPTR = 0x1380;
    uint256 internal constant   QUOTIENT_EVAL_MPTR = 0x13a0;
    uint256 internal constant      QUOTIENT_X_MPTR = 0x13c0;
    uint256 internal constant      QUOTIENT_Y_MPTR = 0x13e0;
    uint256 internal constant          R_EVAL_MPTR = 0x1400;
    uint256 internal constant   PAIRING_LHS_X_MPTR = 0x1420;
    uint256 internal constant   PAIRING_LHS_Y_MPTR = 0x1440;
    uint256 internal constant   PAIRING_RHS_X_MPTR = 0x1460;
    uint256 internal constant   PAIRING_RHS_Y_MPTR = 0x1480;

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) public returns (bool) {
        assembly {
            // Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20),
            // and check if the point is on affine plane,
            // and store them in (hash_mptr, hash_mptr + 0x20).
            // Return updated (success, proof_cptr, hash_mptr).
            function read_ec_point(success, proof_cptr, hash_mptr, q) -> ret0, ret1, ret2 {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret0 := and(success, lt(x, q))
                ret0 := and(ret0, lt(y, q))
                ret0 := and(ret0, eq(mulmod(y, y, q), addmod(mulmod(x, mulmod(x, x, q), q), 3, q)))
                mstore(hash_mptr, x)
                mstore(add(hash_mptr, 0x20), y)
                ret1 := add(proof_cptr, 0x40)
                ret2 := add(hash_mptr, 0x40)
            }

            // Squeeze challenge by keccak256(memory[0..hash_mptr]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr, hash_mptr).
            function squeeze_challenge(challenge_mptr, hash_mptr, r) -> ret0, ret1 {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze challenge without absorbing new input from calldata,
            // by putting an extra 0x01 in memory[0x20] and squeeze by keccak256(memory[0..21]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr).
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Batch invert values in memory[mptr_start..mptr_end] in place.
            // Return updated (success).
            function batch_invert(success, mptr_start, mptr_end, r) -> ret {
                let gp_mptr := mptr_end
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for
                    {}
                    lt(mptr, sub(mptr_end, 0x20))
                    {}
                {
                    gp := mulmod(gp, mload(mptr), r)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), r)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(r, 2))
                mstore(add(gp_mptr, 0xa0), r)
                ret := and(success, staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20))
                let all_inv := mload(gp_mptr)

                let first_mptr := mptr_start
                let second_mptr := add(first_mptr, 0x20)
                gp_mptr := sub(gp_mptr, 0x20)
                for
                    {}
                    lt(second_mptr, mptr)
                    {}
                {
                    let inv := mulmod(all_inv, mload(gp_mptr), r)
                    all_inv := mulmod(all_inv, mload(mptr), r)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(second_mptr), r)
                let inv_second := mulmod(all_inv, mload(first_mptr), r)
                mstore(first_mptr, inv_first)
                mstore(second_mptr, inv_second)
            }

            // Add (x, y) into point at (0x00, 0x20).
            // Return updated (success).
            function ec_add_acc(success, x, y) -> ret {
                mstore(0x40, x)
                mstore(0x60, y)
                ret := and(success, staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40))
            }

            // Scale point at (0x00, 0x20) by scalar.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x40, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x00, 0x60, 0x00, 0x40))
            }

            // Add (x, y) into point at (0x80, 0xa0).
            // Return updated (success).
            function ec_add_tmp(success, x, y) -> ret {
                mstore(0xc0, x)
                mstore(0xe0, y)
                ret := and(success, staticcall(gas(), 0x06, 0x80, 0x80, 0x80, 0x40))
            }

            // Scale point at (0x80, 0xa0) by scalar.
            // Return updated (success).
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0xc0, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x80, 0x60, 0x80, 0x40))
            }

            // Perform pairing check.
            // Return updated (success).
            function ec_pairing(success, lhs_x, lhs_y, rhs_x, rhs_y) -> ret {
                mstore(0x00, lhs_x)
                mstore(0x20, lhs_y)
                mstore(0x40, mload(G2_X_1_MPTR))
                mstore(0x60, mload(G2_X_2_MPTR))
                mstore(0x80, mload(G2_Y_1_MPTR))
                mstore(0xa0, mload(G2_Y_2_MPTR))
                mstore(0xc0, rhs_x)
                mstore(0xe0, rhs_y)
                mstore(0x100, mload(NEG_S_G2_X_1_MPTR))
                mstore(0x120, mload(NEG_S_G2_X_2_MPTR))
                mstore(0x140, mload(NEG_S_G2_Y_1_MPTR))
                mstore(0x160, mload(NEG_S_G2_Y_2_MPTR))
                ret := and(success, staticcall(gas(), 0x08, 0x00, 0x180, 0x00, 0x20))
                ret := and(ret, mload(0x00))
            }

            // Modulus
            let q := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // BN254 base field
            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // BN254 scalar field

            // Initialize success as true
            let success := true

            {
                // Load vk_digest and num_instances of vk into memory
                mstore(0x06c0, 0x10fa432e037aeb212cb11a4cf27da42780d01d0a6e1fc881c85ced8145ec5275) // vk_digest
                mstore(0x06e0, 0x0000000000000000000000000000000000000000000000000000000000000031) // num_instances

                // Check valid length of proof
                success := and(success, eq(0x1180, calldataload(PROOF_LEN_CPTR)))

                // Check valid length of instances
                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(success, eq(num_instances, calldataload(NUM_INSTANCE_CPTR)))

                // Absorb vk diegst
                mstore(0x00, mload(VK_DIGEST_MPTR))

                // Read instances and witness commitments and generate challenges
                let hash_mptr := 0x20
                let instance_cptr := INSTANCE_CPTR
                for
                    { let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances)) }
                    lt(instance_cptr, instance_cptr_end)
                    {}
                {
                    let instance := calldataload(instance_cptr)
                    success := and(success, lt(instance, r))
                    mstore(hash_mptr, instance)
                    instance_cptr := add(instance_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                let proof_cptr := PROOF_CPTR
                let challenge_mptr := CHALLENGE_MPTR

                // Phase 1
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0140) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 2
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0280) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)

                // Phase 3
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0240) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 4
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0140) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Read evaluations
                for
                    { let proof_cptr_end := add(proof_cptr, 0x09c0) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    let eval := calldataload(proof_cptr)
                    success := and(success, lt(eval, r))
                    mstore(hash_mptr, eval)
                    proof_cptr := add(proof_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                // Read batch opening proof and generate challenges
                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // zeta
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)                        // nu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // mu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W'

                // Load full vk into memory
                mstore(0x06c0, 0x10fa432e037aeb212cb11a4cf27da42780d01d0a6e1fc881c85ced8145ec5275) // vk_digest
                mstore(0x06e0, 0x0000000000000000000000000000000000000000000000000000000000000031) // num_instances
                mstore(0x0700, 0x0000000000000000000000000000000000000000000000000000000000000012) // k
                mstore(0x0720, 0x30644259cd94e7dd5045d7a27013b7fcd21c9e3b7fa75222e7bda49b729b0401) // n_inv
                mstore(0x0740, 0x0f60c8fe0414cb9379b2d39267945f6bd60d06a05216231b26a9fcf88ddbfebe) // omega
                mstore(0x0760, 0x0e1165d221ab96da2bb4efe1b8fbf541b58d00917384a41bc6ab624d6d3e2b76) // omega_inv
                mstore(0x0780, 0x15a9c33a6d34b8fb8e5c3ff61814ca50c878ed14bc17d9442cd5c127bf33fd6d) // omega_inv_to_l
                mstore(0x07a0, 0x0000000000000000000000000000000000000000000000000000000000000000) // has_accumulator
                mstore(0x07c0, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
                mstore(0x07e0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limbs
                mstore(0x0800, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limb_bits
                mstore(0x0820, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
                mstore(0x0840, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
                mstore(0x0860, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
                mstore(0x0880, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
                mstore(0x08a0, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
                mstore(0x08c0, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
                mstore(0x08e0, 0x186282957db913abd99f91db59fe69922e95040603ef44c0bd7aa3adeef8f5ac) // neg_s_g2_x_1
                mstore(0x0900, 0x17944351223333f260ddc3b4af45191b856689eda9eab5cbcddbbe570ce860d2) // neg_s_g2_x_2
                mstore(0x0920, 0x06d971ff4a7467c3ec596ed6efc674572e32fd6f52b721f97e35b0b3d3546753) // neg_s_g2_y_1
                mstore(0x0940, 0x06ecdb9f9567f59ed2eee36e1e1d58797fd13cc97fafc2910f5e8a12f202fa9a) // neg_s_g2_y_2
                mstore(0x0960, 0x00bc6388571acab02cda68e5a8bc270814901720cfbea81eb8724c7af531c569) // fixed_comms[0].x
                mstore(0x0980, 0x200a4872e44dca25c35665326a6f93e4d9da70ff6973dcb9d5e0b42c3ce116af) // fixed_comms[0].y
                mstore(0x09a0, 0x282550d9ee373535c2ebf3b036f697019936b55058505d0f6189ec8ea21c9acc) // fixed_comms[1].x
                mstore(0x09c0, 0x272751b797197a5724f134145c2498e38007e1f95d4be900adadc6d5b1c3b85b) // fixed_comms[1].y
                mstore(0x09e0, 0x0a983c13efedb3dbde09575a38b084d7cd92bf31ef63a789aa177d6c67496bbd) // fixed_comms[2].x
                mstore(0x0a00, 0x0612474eab97ce1ae19deb0c16119696af7dfa3370f305bf2ab12c7cce5bbfa1) // fixed_comms[2].y
                mstore(0x0a20, 0x27e5aefcf48fab4ca7696853e4bc71988a1cfa552ef96c7a9c87c1373ff18922) // fixed_comms[3].x
                mstore(0x0a40, 0x21c6a2115445443dae670a95f07cdb9f4a88fd5c6a4055a07d5bfdf99da1fb1c) // fixed_comms[3].y
                mstore(0x0a60, 0x0112411ff18c94adbe82d1decc4ced25404ddf0493d5352735f3eb1e577443c8) // fixed_comms[4].x
                mstore(0x0a80, 0x20493c257486ef4cf2eb693e7359acbf6713b3d6b534ef747fae4668d2505af7) // fixed_comms[4].y
                mstore(0x0aa0, 0x15de9e05b85fac65a2c4a7f8778b46fcb7b8bef3f363b35f4ad5385717f7a294) // fixed_comms[5].x
                mstore(0x0ac0, 0x0852909412087958094606c7579c89ab450c5fad58b710151d9be674658304bd) // fixed_comms[5].y
                mstore(0x0ae0, 0x0659b386cf7ccd875ef11622bd16801e87013b56d4a71f49c41f6b6f93d8f3f9) // fixed_comms[6].x
                mstore(0x0b00, 0x0e8975b7bf3282d0f86a202a2761b7ad8a2ec5ee44126eff020da83df3dacabc) // fixed_comms[6].y
                mstore(0x0b20, 0x248ba7caade3d9c870a0fd86122b4f12d4159fff151e046c7329e29f8670b3f0) // fixed_comms[7].x
                mstore(0x0b40, 0x0b53e3ddefc2b34c91767a6bcd90b6ab63986a6fc85ba0f82ff3ede59db95aa3) // fixed_comms[7].y
                mstore(0x0b60, 0x0280950dcf4c88569d4ac09d08a64b1d7e5dda9a92025f3a67831b52cc54f5d3) // fixed_comms[8].x
                mstore(0x0b80, 0x0159a84799c5a2b70e801b709733a9452e0dbc3bcc5fec2b11a17c246fff8172) // fixed_comms[8].y
                mstore(0x0ba0, 0x081a1d562f38b857fb7e200bb455094a011510db9ac0352f4a01fee1674d134d) // fixed_comms[9].x
                mstore(0x0bc0, 0x19421a4d1ab26b52bd8d1826af0c406339c8a4859e24c56dd25a7d7a72632b40) // fixed_comms[9].y
                mstore(0x0be0, 0x098055bc990ea7766dbcd9e68cab85424dbc1e35b475b828ac74bad04a0e4993) // fixed_comms[10].x
                mstore(0x0c00, 0x2dff61482366aedf115b5620ecba51925967fd2b76f882535d3a8440bb9e632e) // fixed_comms[10].y
                mstore(0x0c20, 0x01eaa7a4310ac5481d5c765ac7c2c7f666aaf00d5a7ee700c9237f27640ce87e) // fixed_comms[11].x
                mstore(0x0c40, 0x1cf4fb417ac9b7bcbd4c1ae5732bbc4b9c1c7451b3516e4373472a3b7086e042) // fixed_comms[11].y
                mstore(0x0c60, 0x129c2d2d6b2ca3abdb966561c4d83b5450580863ede453740aa16236a7d0e950) // fixed_comms[12].x
                mstore(0x0c80, 0x221ceefd36ad52d134757be39ef99bd1ac7f7662903f6eec91361c985edc0bdd) // fixed_comms[12].y
                mstore(0x0ca0, 0x2faf1b96f708613100be4ceacf3355f7c17e400039e0f1cfed7ea6e604ff06ab) // fixed_comms[13].x
                mstore(0x0cc0, 0x0c0fda12449a8d3d713fb41226f27ea2c6b5906183098e875d2b94d2d7b96898) // fixed_comms[13].y
                mstore(0x0ce0, 0x0c13a3ad660e1e595d1e8a5363868a756b46b1170d2c968cfe2dcf2adde2b1fa) // fixed_comms[14].x
                mstore(0x0d00, 0x239e78146447abab3b8d795fce6242eb93a0c9b3b919b25e07f8a45cc34f3868) // fixed_comms[14].y
                mstore(0x0d20, 0x051afc90418b9a6baed57d365ffc501a067eec32836012c08a51763f50d3fab2) // fixed_comms[15].x
                mstore(0x0d40, 0x12ddc1d2cf2b2227bfff9ab73f8336caaa1e28b2ad70c8d1a1d78ab85c417e7a) // fixed_comms[15].y
                mstore(0x0d60, 0x29536a715aee15e71ea8ee40775fec828788e3219b7bcfea25394004544d23f1) // fixed_comms[16].x
                mstore(0x0d80, 0x1add119c8075388eb7791920449c32378eb8f17a43043aebb88f498379e4b568) // fixed_comms[16].y
                mstore(0x0da0, 0x1426965bfa5443bbdfb8d1101a5ab0e734161ecc1be23820178e219a0975b4e5) // fixed_comms[17].x
                mstore(0x0dc0, 0x034721b25e503eb1233d61eef6f9102d6c7c975f5fbf181dc8146df122db72d5) // fixed_comms[17].y
                mstore(0x0de0, 0x0c520ec975d97565332531a187896cc85216282f781fba4ad72373d3f9091fd6) // fixed_comms[18].x
                mstore(0x0e00, 0x224bf5aae92cae9ed520b34bf3657ca187a7d0f37503db8fe385f2b6e358acca) // fixed_comms[18].y
                mstore(0x0e20, 0x16e3e5fa3f06db1c4b656ded3d30d5ad9c0f340c87f989c32ff8039cb1c194a2) // fixed_comms[19].x
                mstore(0x0e40, 0x12fc34ef6aa6abf30bd4b81119f6e9048ccd310523a6026867c5233976781b3a) // fixed_comms[19].y
                mstore(0x0e60, 0x15e4d60697a9564cb96c64b988d71b510fb41d872ed625fd097a0fa286adca55) // fixed_comms[20].x
                mstore(0x0e80, 0x1e97db0425468e005063704e9fdd4a924323ad25180dc97a2bce0db16d5affd9) // fixed_comms[20].y
                mstore(0x0ea0, 0x269ff0bc3c43011b5c373d79f21808e67d938665b4290f14c0fbd49150ce6b73) // fixed_comms[21].x
                mstore(0x0ec0, 0x178c99b923272f94ddf9df039b074efa414c4e6759600b744827d4355f15148d) // fixed_comms[21].y
                mstore(0x0ee0, 0x0db0f43b0d089dae35c35c99ecd6195c0235029f6fd7bd9c03e5e78ca6030ec8) // fixed_comms[22].x
                mstore(0x0f00, 0x21d212f61ce096cced931103f4dc96f3979b3923351c7becfdedff8c9ac0b697) // fixed_comms[22].y
                mstore(0x0f20, 0x1d5f006ae4015b1e4cbc02635a094c8c6de11f0b04eaae28e704a1ead9e9933c) // permutation_comms[0].x
                mstore(0x0f40, 0x304b38c2f74d9c4eec40422e16941d546b8ddd34d49f2d34256d7d22f2579481) // permutation_comms[0].y
                mstore(0x0f60, 0x0c705651a938f92b8a38538eaa996e5867332ef8078478ff5a6aa044207a5ca4) // permutation_comms[1].x
                mstore(0x0f80, 0x071ecb2aa841f16186b855dff89e57d0583aa24d18153b1cbba9dbbf0a1bb145) // permutation_comms[1].y
                mstore(0x0fa0, 0x21ecda48829469f0b2b7b2af1aa4a89cbeedc5666d9ca5d86149f79fcad51b7c) // permutation_comms[2].x
                mstore(0x0fc0, 0x271026109abc06e58f82abe9bcd84f8cad084da5b66f307c1e24c83ca2f5528f) // permutation_comms[2].y
                mstore(0x0fe0, 0x05c4977ef409a1eb678fb80fa466d80fe1aeb5bd63d8fb21d3715f5696b6370f) // permutation_comms[3].x
                mstore(0x1000, 0x2aeee08b63d24ffeadf6505b894e1ecfd3e50b33eb5331c290f222d2ef3137cf) // permutation_comms[3].y
                mstore(0x1020, 0x2a74e21bdedfb9fd48b95682b006f8292989f80e8e5fc7c7e946d1fa8fd5aa80) // permutation_comms[4].x
                mstore(0x1040, 0x2c883f46d50365189cb3c7b8d31012e97ab3cc0c2f43498808767c3b2c678ae3) // permutation_comms[4].y
                mstore(0x1060, 0x0e598be5b2d6744a589d3f2997a7bf0f033318156a9b2f947946df18a27ff6dc) // permutation_comms[5].x
                mstore(0x1080, 0x2e46c59b3c5fc53fbe07026dec3b903debf984f4a48933cc773e9f155abadb10) // permutation_comms[5].y
                mstore(0x10a0, 0x1df9d3063bdb368ae737da7b2e62d0ac6af9eadb17e234ae430732c881b7e066) // permutation_comms[6].x
                mstore(0x10c0, 0x1af603ccc57869a723e531dfd8ce2f0b1a2c3ae5dc7f2d02e92b2c49bcb6a843) // permutation_comms[6].y
                mstore(0x10e0, 0x13ab267051d6a77d28fee208708d3b7e8bb36637e441724a5cb96095ed50187a) // permutation_comms[7].x
                mstore(0x1100, 0x262f5493e2aa9d750f56a70fa203b4658b7c9c058097abc6f205bc05941da0aa) // permutation_comms[7].y
                mstore(0x1120, 0x01a7837e6470babb230978a3079af34e382588caaf1c0c791e81f37222798929) // permutation_comms[8].x
                mstore(0x1140, 0x155c9bea95acf37b018196229c82254163940010ab902b96a4dcde67c6a99a6f) // permutation_comms[8].y

                // Read accumulator from instances
                if mload(HAS_ACCUMULATOR_MPTR) {
                    let num_limbs := mload(NUM_ACC_LIMBS_MPTR)
                    let num_limb_bits := mload(NUM_ACC_LIMB_BITS_MPTR)

                    let cptr := add(INSTANCE_CPTR, mul(mload(ACC_OFFSET_MPTR), 0x20))
                    let lhs_y_off := mul(num_limbs, 0x20)
                    let rhs_x_off := mul(lhs_y_off, 2)
                    let rhs_y_off := mul(lhs_y_off, 3)
                    let lhs_x := calldataload(cptr)
                    let lhs_y := calldataload(add(cptr, lhs_y_off))
                    let rhs_x := calldataload(add(cptr, rhs_x_off))
                    let rhs_y := calldataload(add(cptr, rhs_y_off))
                    for
                        {
                            let cptr_end := add(cptr, mul(0x20, num_limbs))
                            let shift := num_limb_bits
                        }
                        lt(cptr, cptr_end)
                        {}
                    {
                        cptr := add(cptr, 0x20)
                        lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))
                        lhs_y := add(lhs_y, shl(shift, calldataload(add(cptr, lhs_y_off))))
                        rhs_x := add(rhs_x, shl(shift, calldataload(add(cptr, rhs_x_off))))
                        rhs_y := add(rhs_y, shl(shift, calldataload(add(cptr, rhs_y_off))))
                        shift := add(shift, num_limb_bits)
                    }

                    success := and(success, eq(mulmod(lhs_y, lhs_y, q), addmod(mulmod(lhs_x, mulmod(lhs_x, lhs_x, q), q), 3, q)))
                    success := and(success, eq(mulmod(rhs_y, rhs_y, q), addmod(mulmod(rhs_x, mulmod(rhs_x, rhs_x, q), q), 3, q)))

                    mstore(ACC_LHS_X_MPTR, lhs_x)
                    mstore(ACC_LHS_Y_MPTR, lhs_y)
                    mstore(ACC_RHS_X_MPTR, rhs_x)
                    mstore(ACC_RHS_Y_MPTR, rhs_y)
                }

                pop(q)
            }

            // Revert earlier if anything from calldata is invalid
            if iszero(success) {
                revert(0, 0)
            }

            // Compute lagrange evaluations and instance evaluation
            {
                let k := mload(K_MPTR)
                let x := mload(X_MPTR)
                let x_n := x
                for
                    { let idx := 0 }
                    lt(idx, k)
                    { idx := add(idx, 1) }
                {
                    x_n := mulmod(x_n, x_n, r)
                }

                let omega := mload(OMEGA_MPTR)

                let mptr := X_N_MPTR
                let mptr_end := add(mptr, mul(0x20, add(mload(NUM_INSTANCES_MPTR), 6)))
                if iszero(mload(NUM_INSTANCES_MPTR)) {
                    mptr_end := add(mptr_end, 0x20)
                }
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, addmod(x, sub(r, pow_of_omega), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }
                let x_n_minus_1 := addmod(x_n, sub(r, 1), r)
                mstore(mptr_end, x_n_minus_1)
                success := batch_invert(success, X_N_MPTR, add(mptr_end, 0x20), r)

                mptr := X_N_MPTR
                let l_i_common := mulmod(x_n_minus_1, mload(N_INV_MPTR), r)
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, mulmod(l_i_common, mulmod(mload(mptr), pow_of_omega, r), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }

                let l_blind := mload(add(X_N_MPTR, 0x20))
                let l_i_cptr := add(X_N_MPTR, 0x40)
                for
                    { let l_i_cptr_end := add(X_N_MPTR, 0xc0) }
                    lt(l_i_cptr, l_i_cptr_end)
                    { l_i_cptr := add(l_i_cptr, 0x20) }
                {
                    l_blind := addmod(l_blind, mload(l_i_cptr), r)
                }

                let instance_eval := 0
                for
                    {
                        let instance_cptr := INSTANCE_CPTR
                        let instance_cptr_end := add(instance_cptr, mul(0x20, mload(NUM_INSTANCES_MPTR)))
                    }
                    lt(instance_cptr, instance_cptr_end)
                    {
                        instance_cptr := add(instance_cptr, 0x20)
                        l_i_cptr := add(l_i_cptr, 0x20)
                    }
                {
                    instance_eval := addmod(instance_eval, mulmod(mload(l_i_cptr), calldataload(instance_cptr), r), r)
                }

                let x_n_minus_1_inv := mload(mptr_end)
                let l_last := mload(X_N_MPTR)
                let l_0 := mload(add(X_N_MPTR, 0xc0))

                mstore(X_N_MPTR, x_n)
                mstore(X_N_MINUS_1_INV_MPTR, x_n_minus_1_inv)
                mstore(L_LAST_MPTR, l_last)
                mstore(L_BLIND_MPTR, l_blind)
                mstore(L_0_MPTR, l_0)
                mstore(INSTANCE_EVAL_MPTR, instance_eval)
            }

            // Compute quotient evavluation
            {
                let quotient_eval_numer
                let delta := 4131629893567559867359510883348571134090853742863529169391034518566172092834
                let y := mload(Y_MPTR)
                {
                    let a_0 := calldataload(0x07a4)
                    let f_0 := calldataload(0x0924)
                    let var0 := mulmod(a_0, f_0, r)
                    let a_1 := calldataload(0x07c4)
                    let f_1 := calldataload(0x0944)
                    let var1 := mulmod(a_1, f_1, r)
                    let var2 := addmod(var0, var1, r)
                    let a_2 := calldataload(0x07e4)
                    let f_2 := calldataload(0x0964)
                    let var3 := mulmod(a_2, f_2, r)
                    let var4 := addmod(var2, var3, r)
                    let a_3 := calldataload(0x0804)
                    let f_3 := calldataload(0x0984)
                    let var5 := mulmod(a_3, f_3, r)
                    let var6 := addmod(var4, var5, r)
                    let a_4 := calldataload(0x0824)
                    let f_4 := calldataload(0x09a4)
                    let var7 := mulmod(a_4, f_4, r)
                    let var8 := addmod(var6, var7, r)
                    let var9 := mulmod(a_0, a_1, r)
                    let f_5 := calldataload(0x09e4)
                    let var10 := mulmod(var9, f_5, r)
                    let var11 := addmod(var8, var10, r)
                    let var12 := mulmod(a_2, a_3, r)
                    let f_6 := calldataload(0x0a04)
                    let var13 := mulmod(var12, f_6, r)
                    let var14 := addmod(var11, var13, r)
                    let f_7 := calldataload(0x09c4)
                    let a_4_next_1 := calldataload(0x0844)
                    let var15 := mulmod(f_7, a_4_next_1, r)
                    let var16 := addmod(var14, var15, r)
                    let f_8 := calldataload(0x0a24)
                    let var17 := addmod(var16, f_8, r)
                    quotient_eval_numer := var17
                }
                {
                    let f_20 := calldataload(0x0ba4)
                    let a_0 := calldataload(0x07a4)
                    let f_12 := calldataload(0x0b04)
                    let var0 := addmod(a_0, f_12, r)
                    let var1 := mulmod(var0, var0, r)
                    let var2 := mulmod(var1, var1, r)
                    let var3 := mulmod(var2, var0, r)
                    let var4 := mulmod(var3, 0x109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b, r)
                    let a_1 := calldataload(0x07c4)
                    let f_13 := calldataload(0x0b24)
                    let var5 := addmod(a_1, f_13, r)
                    let var6 := mulmod(var5, var5, r)
                    let var7 := mulmod(var6, var6, r)
                    let var8 := mulmod(var7, var5, r)
                    let var9 := mulmod(var8, 0x16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0, r)
                    let var10 := addmod(var4, var9, r)
                    let a_2 := calldataload(0x07e4)
                    let f_14 := calldataload(0x0b44)
                    let var11 := addmod(a_2, f_14, r)
                    let var12 := mulmod(var11, var11, r)
                    let var13 := mulmod(var12, var12, r)
                    let var14 := mulmod(var13, var11, r)
                    let var15 := mulmod(var14, 0x2b90bba00fca0589f617e7dcbfe82e0df706ab640ceb247b791a93b74e36736d, r)
                    let var16 := addmod(var10, var15, r)
                    let a_0_next_1 := calldataload(0x0864)
                    let var17 := sub(r, a_0_next_1)
                    let var18 := addmod(var16, var17, r)
                    let var19 := mulmod(f_20, var18, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var19, r)
                }
                {
                    let f_20 := calldataload(0x0ba4)
                    let a_0 := calldataload(0x07a4)
                    let f_12 := calldataload(0x0b04)
                    let var0 := addmod(a_0, f_12, r)
                    let var1 := mulmod(var0, var0, r)
                    let var2 := mulmod(var1, var1, r)
                    let var3 := mulmod(var2, var0, r)
                    let var4 := mulmod(var3, 0x2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771, r)
                    let a_1 := calldataload(0x07c4)
                    let f_13 := calldataload(0x0b24)
                    let var5 := addmod(a_1, f_13, r)
                    let var6 := mulmod(var5, var5, r)
                    let var7 := mulmod(var6, var6, r)
                    let var8 := mulmod(var7, var5, r)
                    let var9 := mulmod(var8, 0x2e2419f9ec02ec394c9871c832963dc1b89d743c8c7b964029b2311687b1fe23, r)
                    let var10 := addmod(var4, var9, r)
                    let a_2 := calldataload(0x07e4)
                    let f_14 := calldataload(0x0b44)
                    let var11 := addmod(a_2, f_14, r)
                    let var12 := mulmod(var11, var11, r)
                    let var13 := mulmod(var12, var12, r)
                    let var14 := mulmod(var13, var11, r)
                    let var15 := mulmod(var14, 0x101071f0032379b697315876690f053d148d4e109f5fb065c8aacc55a0f89bfa, r)
                    let var16 := addmod(var10, var15, r)
                    let a_1_next_1 := calldataload(0x0884)
                    let var17 := sub(r, a_1_next_1)
                    let var18 := addmod(var16, var17, r)
                    let var19 := mulmod(f_20, var18, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var19, r)
                }
                {
                    let f_20 := calldataload(0x0ba4)
                    let a_0 := calldataload(0x07a4)
                    let f_12 := calldataload(0x0b04)
                    let var0 := addmod(a_0, f_12, r)
                    let var1 := mulmod(var0, var0, r)
                    let var2 := mulmod(var1, var1, r)
                    let var3 := mulmod(var2, var0, r)
                    let var4 := mulmod(var3, 0x143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7, r)
                    let a_1 := calldataload(0x07c4)
                    let f_13 := calldataload(0x0b24)
                    let var5 := addmod(a_1, f_13, r)
                    let var6 := mulmod(var5, var5, r)
                    let var7 := mulmod(var6, var6, r)
                    let var8 := mulmod(var7, var5, r)
                    let var9 := mulmod(var8, 0x176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911, r)
                    let var10 := addmod(var4, var9, r)
                    let a_2 := calldataload(0x07e4)
                    let f_14 := calldataload(0x0b44)
                    let var11 := addmod(a_2, f_14, r)
                    let var12 := mulmod(var11, var11, r)
                    let var13 := mulmod(var12, var12, r)
                    let var14 := mulmod(var13, var11, r)
                    let var15 := mulmod(var14, 0x19a3fc0a56702bf417ba7fee3802593fa644470307043f7773279cd71d25d5e0, r)
                    let var16 := addmod(var10, var15, r)
                    let a_2_next_1 := calldataload(0x08a4)
                    let var17 := sub(r, a_2_next_1)
                    let var18 := addmod(var16, var17, r)
                    let var19 := mulmod(f_20, var18, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var19, r)
                }
                {
                    let f_21 := calldataload(0x0bc4)
                    let a_0 := calldataload(0x07a4)
                    let f_12 := calldataload(0x0b04)
                    let var0 := addmod(a_0, f_12, r)
                    let var1 := mulmod(var0, var0, r)
                    let var2 := mulmod(var1, var1, r)
                    let var3 := mulmod(var2, var0, r)
                    let a_3 := calldataload(0x0804)
                    let var4 := sub(r, a_3)
                    let var5 := addmod(var3, var4, r)
                    let var6 := mulmod(f_21, var5, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var6, r)
                }
                {
                    let f_21 := calldataload(0x0bc4)
                    let a_3 := calldataload(0x0804)
                    let var0 := mulmod(a_3, 0x109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b, r)
                    let a_1 := calldataload(0x07c4)
                    let f_13 := calldataload(0x0b24)
                    let var1 := addmod(a_1, f_13, r)
                    let var2 := mulmod(var1, 0x16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0, r)
                    let var3 := addmod(var0, var2, r)
                    let a_2 := calldataload(0x07e4)
                    let f_14 := calldataload(0x0b44)
                    let var4 := addmod(a_2, f_14, r)
                    let var5 := mulmod(var4, 0x2b90bba00fca0589f617e7dcbfe82e0df706ab640ceb247b791a93b74e36736d, r)
                    let var6 := addmod(var3, var5, r)
                    let f_15 := calldataload(0x0aa4)
                    let var7 := addmod(var6, f_15, r)
                    let var8 := mulmod(var7, var7, r)
                    let var9 := mulmod(var8, var8, r)
                    let var10 := mulmod(var9, var7, r)
                    let a_0_next_1 := calldataload(0x0864)
                    let var11 := mulmod(a_0_next_1, 0x203d1d351372bf15b6465d69d3e12806879a5f36b4ba6dd17dfea07d03f82f26, r)
                    let a_1_next_1 := calldataload(0x0884)
                    let var12 := mulmod(a_1_next_1, 0x29b6537218615bcb4b6ad7fe4620063d48e42ce2096b3a1d6e320628bb032c22, r)
                    let var13 := addmod(var11, var12, r)
                    let a_2_next_1 := calldataload(0x08a4)
                    let var14 := mulmod(a_2_next_1, 0x11551257de3d4b5ab51bd377d7bb55c054f51f711623515b1e2a35a958b93a6a, r)
                    let var15 := addmod(var13, var14, r)
                    let var16 := sub(r, var15)
                    let var17 := addmod(var10, var16, r)
                    let var18 := mulmod(f_21, var17, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var18, r)
                }
                {
                    let f_21 := calldataload(0x0bc4)
                    let a_3 := calldataload(0x0804)
                    let var0 := mulmod(a_3, 0x2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771, r)
                    let a_1 := calldataload(0x07c4)
                    let f_13 := calldataload(0x0b24)
                    let var1 := addmod(a_1, f_13, r)
                    let var2 := mulmod(var1, 0x2e2419f9ec02ec394c9871c832963dc1b89d743c8c7b964029b2311687b1fe23, r)
                    let var3 := addmod(var0, var2, r)
                    let a_2 := calldataload(0x07e4)
                    let f_14 := calldataload(0x0b44)
                    let var4 := addmod(a_2, f_14, r)
                    let var5 := mulmod(var4, 0x101071f0032379b697315876690f053d148d4e109f5fb065c8aacc55a0f89bfa, r)
                    let var6 := addmod(var3, var5, r)
                    let f_16 := calldataload(0x0ac4)
                    let var7 := addmod(var6, f_16, r)
                    let a_0_next_1 := calldataload(0x0864)
                    let var8 := mulmod(a_0_next_1, 0x29dedb1bbf80c8863d569912c20f1f82bf0dc3bc4fb62798dd1319814f833b54, r)
                    let a_1_next_1 := calldataload(0x0884)
                    let var9 := mulmod(a_1_next_1, 0x130b59143f4e340cd66c7251dc8f56fbbe0367fec1575cb124ca8a66304e3849, r)
                    let var10 := addmod(var8, var9, r)
                    let a_2_next_1 := calldataload(0x08a4)
                    let var11 := mulmod(a_2_next_1, 0x0c2808c9533e2c526087842fb62521a3248c8d6d3b16d4b4108476d2eeda95f9, r)
                    let var12 := addmod(var10, var11, r)
                    let var13 := sub(r, var12)
                    let var14 := addmod(var7, var13, r)
                    let var15 := mulmod(f_21, var14, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_21 := calldataload(0x0bc4)
                    let a_3 := calldataload(0x0804)
                    let var0 := mulmod(a_3, 0x143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7, r)
                    let a_1 := calldataload(0x07c4)
                    let f_13 := calldataload(0x0b24)
                    let var1 := addmod(a_1, f_13, r)
                    let var2 := mulmod(var1, 0x176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911, r)
                    let var3 := addmod(var0, var2, r)
                    let a_2 := calldataload(0x07e4)
                    let f_14 := calldataload(0x0b44)
                    let var4 := addmod(a_2, f_14, r)
                    let var5 := mulmod(var4, 0x19a3fc0a56702bf417ba7fee3802593fa644470307043f7773279cd71d25d5e0, r)
                    let var6 := addmod(var3, var5, r)
                    let f_17 := calldataload(0x0ae4)
                    let var7 := addmod(var6, f_17, r)
                    let a_0_next_1 := calldataload(0x0864)
                    let var8 := mulmod(a_0_next_1, 0x0173249a1c9eac2591706fe09af22cfd29e1387e706cf0ded2889dc145c61609, r)
                    let a_1_next_1 := calldataload(0x0884)
                    let var9 := mulmod(a_1_next_1, 0x0abc7f158780841ec82e03ec3cee0cf1d16270b0238f3063d2e5fb5138e59350, r)
                    let var10 := addmod(var8, var9, r)
                    let a_2_next_1 := calldataload(0x08a4)
                    let var11 := mulmod(a_2_next_1, 0x1738a318c8631b6e8305505aaf3b497fe9f2478c2f28ee945413af26963b4700, r)
                    let var12 := addmod(var10, var11, r)
                    let var13 := sub(r, var12)
                    let var14 := addmod(var7, var13, r)
                    let var15 := mulmod(f_21, var14, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_22 := calldataload(0x0be4)
                    let a_0_prev_1 := calldataload(0x08e4)
                    let a_0 := calldataload(0x07a4)
                    let var0 := addmod(a_0_prev_1, a_0, r)
                    let a_0_next_1 := calldataload(0x0864)
                    let var1 := sub(r, a_0_next_1)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_22, var2, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var3, r)
                }
                {
                    let f_22 := calldataload(0x0be4)
                    let a_1_prev_1 := calldataload(0x0904)
                    let a_1 := calldataload(0x07c4)
                    let var0 := addmod(a_1_prev_1, a_1, r)
                    let a_1_next_1 := calldataload(0x0884)
                    let var1 := sub(r, a_1_next_1)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_22, var2, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var3, r)
                }
                {
                    let f_22 := calldataload(0x0be4)
                    let a_2_prev_1 := calldataload(0x08c4)
                    let a_2_next_1 := calldataload(0x08a4)
                    let var0 := sub(r, a_2_next_1)
                    let var1 := addmod(a_2_prev_1, var0, r)
                    let var2 := mulmod(f_22, var1, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var2, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, sub(r, mulmod(l_0, calldataload(0x0d44), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let perm_z_last := calldataload(0x0e04)
                    let eval := mulmod(mload(L_LAST_MPTR), addmod(mulmod(perm_z_last, perm_z_last, r), sub(r, perm_z_last), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0da4), sub(r, calldataload(0x0d84)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0e04), sub(r, calldataload(0x0de4)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0d64)
                    let rhs := calldataload(0x0d44)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x07a4), mulmod(beta, calldataload(0x0c24), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x07c4), mulmod(beta, calldataload(0x0c44), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x07e4), mulmod(beta, calldataload(0x0c64), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0804), mulmod(beta, calldataload(0x0c84), r), r), gamma, r), r)
                    mstore(0x00, mulmod(beta, mload(X_MPTR), r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x07a4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x07c4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x07e4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0804), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0dc4)
                    let rhs := calldataload(0x0da4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0824), mulmod(beta, calldataload(0x0ca4), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mulmod(beta, calldataload(0x0cc4), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0aa4), mulmod(beta, calldataload(0x0ce4), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0ac4), mulmod(beta, calldataload(0x0d04), r), r), gamma, r), r)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0824), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0aa4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0ac4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0e24)
                    let rhs := calldataload(0x0e04)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0ae4), mulmod(beta, calldataload(0x0d24), r), r), gamma, r), r)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0ae4), mload(0x00), r), gamma, r), r)
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, mulmod(l_0, sub(r, calldataload(0x0e44)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, addmod(mulmod(calldataload(0x0e44), calldataload(0x0e44), r), sub(r, calldataload(0x0e44)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let input
                    {
                        let f_18 := calldataload(0x0b64)
                        let var0 := 0x5
                        let var1 := mulmod(f_18, var0, r)
                        let a_0 := calldataload(0x07a4)
                        let var2 := mulmod(f_18, a_0, r)
                        input := var1
                        input := addmod(mulmod(input, theta, r), var2, r)
                    }
                    let table
                    {
                        let f_9 := calldataload(0x0a44)
                        let f_10 := calldataload(0x0a64)
                        table := f_9
                        table := addmod(mulmod(table, theta, r), f_10, r)
                    }
                    let beta := mload(BETA_MPTR)
                    let gamma := mload(GAMMA_MPTR)
                    let lhs := mulmod(calldataload(0x0e64), mulmod(addmod(calldataload(0x0e84), beta, r), addmod(calldataload(0x0ec4), gamma, r), r), r)
                    let rhs := mulmod(calldataload(0x0e44), mulmod(addmod(input, beta, r), addmod(table, gamma, r), r), r)
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0e84), sub(r, calldataload(0x0ec4)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), mulmod(addmod(calldataload(0x0e84), sub(r, calldataload(0x0ec4)), r), addmod(calldataload(0x0e84), sub(r, calldataload(0x0ea4)), r), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, mulmod(l_0, sub(r, calldataload(0x0ee4)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, addmod(mulmod(calldataload(0x0ee4), calldataload(0x0ee4), r), sub(r, calldataload(0x0ee4)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let input
                    {
                        let f_18 := calldataload(0x0b64)
                        let var0 := 0x5
                        let var1 := mulmod(f_18, var0, r)
                        let a_1 := calldataload(0x07c4)
                        let var2 := mulmod(f_18, a_1, r)
                        input := var1
                        input := addmod(mulmod(input, theta, r), var2, r)
                    }
                    let table
                    {
                        let f_9 := calldataload(0x0a44)
                        let f_10 := calldataload(0x0a64)
                        table := f_9
                        table := addmod(mulmod(table, theta, r), f_10, r)
                    }
                    let beta := mload(BETA_MPTR)
                    let gamma := mload(GAMMA_MPTR)
                    let lhs := mulmod(calldataload(0x0f04), mulmod(addmod(calldataload(0x0f24), beta, r), addmod(calldataload(0x0f64), gamma, r), r), r)
                    let rhs := mulmod(calldataload(0x0ee4), mulmod(addmod(input, beta, r), addmod(table, gamma, r), r), r)
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0f24), sub(r, calldataload(0x0f64)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), mulmod(addmod(calldataload(0x0f24), sub(r, calldataload(0x0f64)), r), addmod(calldataload(0x0f24), sub(r, calldataload(0x0f44)), r), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, mulmod(l_0, sub(r, calldataload(0x0f84)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, addmod(mulmod(calldataload(0x0f84), calldataload(0x0f84), r), sub(r, calldataload(0x0f84)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let input
                    {
                        let f_18 := calldataload(0x0b64)
                        let var0 := 0x5
                        let var1 := mulmod(f_18, var0, r)
                        let a_2 := calldataload(0x07e4)
                        let var2 := mulmod(f_18, a_2, r)
                        input := var1
                        input := addmod(mulmod(input, theta, r), var2, r)
                    }
                    let table
                    {
                        let f_9 := calldataload(0x0a44)
                        let f_10 := calldataload(0x0a64)
                        table := f_9
                        table := addmod(mulmod(table, theta, r), f_10, r)
                    }
                    let beta := mload(BETA_MPTR)
                    let gamma := mload(GAMMA_MPTR)
                    let lhs := mulmod(calldataload(0x0fa4), mulmod(addmod(calldataload(0x0fc4), beta, r), addmod(calldataload(0x1004), gamma, r), r), r)
                    let rhs := mulmod(calldataload(0x0f84), mulmod(addmod(input, beta, r), addmod(table, gamma, r), r), r)
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0fc4), sub(r, calldataload(0x1004)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), mulmod(addmod(calldataload(0x0fc4), sub(r, calldataload(0x1004)), r), addmod(calldataload(0x0fc4), sub(r, calldataload(0x0fe4)), r), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, mulmod(l_0, sub(r, calldataload(0x1024)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, addmod(mulmod(calldataload(0x1024), calldataload(0x1024), r), sub(r, calldataload(0x1024)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let input
                    {
                        let f_18 := calldataload(0x0b64)
                        let var0 := 0x5
                        let var1 := mulmod(f_18, var0, r)
                        let a_3 := calldataload(0x0804)
                        let var2 := mulmod(f_18, a_3, r)
                        input := var1
                        input := addmod(mulmod(input, theta, r), var2, r)
                    }
                    let table
                    {
                        let f_9 := calldataload(0x0a44)
                        let f_10 := calldataload(0x0a64)
                        table := f_9
                        table := addmod(mulmod(table, theta, r), f_10, r)
                    }
                    let beta := mload(BETA_MPTR)
                    let gamma := mload(GAMMA_MPTR)
                    let lhs := mulmod(calldataload(0x1044), mulmod(addmod(calldataload(0x1064), beta, r), addmod(calldataload(0x10a4), gamma, r), r), r)
                    let rhs := mulmod(calldataload(0x1024), mulmod(addmod(input, beta, r), addmod(table, gamma, r), r), r)
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x1064), sub(r, calldataload(0x10a4)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), mulmod(addmod(calldataload(0x1064), sub(r, calldataload(0x10a4)), r), addmod(calldataload(0x1064), sub(r, calldataload(0x1084)), r), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, mulmod(l_0, sub(r, calldataload(0x10c4)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, addmod(mulmod(calldataload(0x10c4), calldataload(0x10c4), r), sub(r, calldataload(0x10c4)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let input
                    {
                        let f_11 := calldataload(0x0a84)
                        let f_19 := calldataload(0x0b84)
                        let a_0 := calldataload(0x07a4)
                        let var0 := mulmod(f_19, a_0, r)
                        input := f_11
                        input := addmod(mulmod(input, theta, r), var0, r)
                    }
                    let table
                    {
                        let f_9 := calldataload(0x0a44)
                        let f_10 := calldataload(0x0a64)
                        table := f_9
                        table := addmod(mulmod(table, theta, r), f_10, r)
                    }
                    let beta := mload(BETA_MPTR)
                    let gamma := mload(GAMMA_MPTR)
                    let lhs := mulmod(calldataload(0x10e4), mulmod(addmod(calldataload(0x1104), beta, r), addmod(calldataload(0x1144), gamma, r), r), r)
                    let rhs := mulmod(calldataload(0x10c4), mulmod(addmod(input, beta, r), addmod(table, gamma, r), r), r)
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x1104), sub(r, calldataload(0x1144)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), mulmod(addmod(calldataload(0x1104), sub(r, calldataload(0x1144)), r), addmod(calldataload(0x1104), sub(r, calldataload(0x1124)), r), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }

                pop(y)
                pop(delta)

                let quotient_eval := mulmod(quotient_eval_numer, mload(X_N_MINUS_1_INV_MPTR), r)
                mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            }

            // Compute quotient commitment
            {
                mstore(0x00, calldataload(LAST_QUOTIENT_X_CPTR))
                mstore(0x20, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x20)))
                let x_n := mload(X_N_MPTR)
                for
                    {
                        let cptr := sub(LAST_QUOTIENT_X_CPTR, 0x40)
                        let cptr_end := sub(FIRST_QUOTIENT_X_CPTR, 0x40)
                    }
                    lt(cptr_end, cptr)
                    {}
                {
                    success := ec_mul_acc(success, x_n)
                    success := ec_add_acc(success, calldataload(cptr), calldataload(add(cptr, 0x20)))
                    cptr := sub(cptr, 0x40)
                }
                mstore(QUOTIENT_X_MPTR, mload(0x00))
                mstore(QUOTIENT_Y_MPTR, mload(0x20))
            }

            // Compute pairing lhs and rhs
            {
                {
                    let x := mload(X_MPTR)
                    let omega := mload(OMEGA_MPTR)
                    let omega_inv := mload(OMEGA_INV_MPTR)
                    let x_pow_of_omega := mulmod(x, omega, r)
                    mstore(0x0420, x_pow_of_omega)
                    mstore(0x0400, x)
                    x_pow_of_omega := mulmod(x, omega_inv, r)
                    mstore(0x03e0, x_pow_of_omega)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    mstore(0x03c0, x_pow_of_omega)
                }
                {
                    let mu := mload(MU_MPTR)
                    for
                        {
                            let mptr := 0x0440
                            let mptr_end := 0x04c0
                            let point_mptr := 0x03c0
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            point_mptr := add(point_mptr, 0x20)
                        }
                    {
                        mstore(mptr, addmod(mu, sub(r, mload(point_mptr)), r))
                    }
                    let s
                    s := mload(0x0460)
                    s := mulmod(s, mload(0x0480), r)
                    s := mulmod(s, mload(0x04a0), r)
                    mstore(0x04c0, s)
                    let diff
                    diff := mload(0x0440)
                    mstore(0x04e0, diff)
                    mstore(0x00, diff)
                    diff := mload(0x0440)
                    diff := mulmod(diff, mload(0x0460), r)
                    diff := mulmod(diff, mload(0x04a0), r)
                    mstore(0x0500, diff)
                    diff := mload(0x0440)
                    diff := mulmod(diff, mload(0x0460), r)
                    mstore(0x0520, diff)
                    diff := mload(0x0460)
                    mstore(0x0540, diff)
                    diff := mload(0x0440)
                    diff := mulmod(diff, mload(0x04a0), r)
                    mstore(0x0560, diff)
                }
                {
                    let point_1 := mload(0x03e0)
                    let point_2 := mload(0x0400)
                    let point_3 := mload(0x0420)
                    let coeff
                    coeff := addmod(point_1, sub(r, point_2), r)
                    coeff := mulmod(coeff, addmod(point_1, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, mload(0x0460), r)
                    mstore(0x20, coeff)
                    coeff := addmod(point_2, sub(r, point_1), r)
                    coeff := mulmod(coeff, addmod(point_2, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, mload(0x0480), r)
                    mstore(0x40, coeff)
                    coeff := addmod(point_3, sub(r, point_1), r)
                    coeff := mulmod(coeff, addmod(point_3, sub(r, point_2), r), r)
                    coeff := mulmod(coeff, mload(0x04a0), r)
                    mstore(0x60, coeff)
                }
                {
                    let point_2 := mload(0x0400)
                    let coeff
                    coeff := 1
                    coeff := mulmod(coeff, mload(0x0480), r)
                    mstore(0x80, coeff)
                }
                {
                    let point_2 := mload(0x0400)
                    let point_3 := mload(0x0420)
                    let coeff
                    coeff := addmod(point_2, sub(r, point_3), r)
                    coeff := mulmod(coeff, mload(0x0480), r)
                    mstore(0xa0, coeff)
                    coeff := addmod(point_3, sub(r, point_2), r)
                    coeff := mulmod(coeff, mload(0x04a0), r)
                    mstore(0xc0, coeff)
                }
                {
                    let point_0 := mload(0x03c0)
                    let point_2 := mload(0x0400)
                    let point_3 := mload(0x0420)
                    let coeff
                    coeff := addmod(point_0, sub(r, point_2), r)
                    coeff := mulmod(coeff, addmod(point_0, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, mload(0x0440), r)
                    mstore(0xe0, coeff)
                    coeff := addmod(point_2, sub(r, point_0), r)
                    coeff := mulmod(coeff, addmod(point_2, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, mload(0x0480), r)
                    mstore(0x0100, coeff)
                    coeff := addmod(point_3, sub(r, point_0), r)
                    coeff := mulmod(coeff, addmod(point_3, sub(r, point_2), r), r)
                    coeff := mulmod(coeff, mload(0x04a0), r)
                    mstore(0x0120, coeff)
                }
                {
                    let point_1 := mload(0x03e0)
                    let point_2 := mload(0x0400)
                    let coeff
                    coeff := addmod(point_1, sub(r, point_2), r)
                    coeff := mulmod(coeff, mload(0x0460), r)
                    mstore(0x0140, coeff)
                    coeff := addmod(point_2, sub(r, point_1), r)
                    coeff := mulmod(coeff, mload(0x0480), r)
                    mstore(0x0160, coeff)
                }
                {
                    success := batch_invert(success, 0, 0x0180, r)
                    let diff_0_inv := mload(0x00)
                    mstore(0x04e0, diff_0_inv)
                    for
                        {
                            let mptr := 0x0500
                            let mptr_end := 0x0580
                        }
                        lt(mptr, mptr_end)
                        { mptr := add(mptr, 0x20) }
                    {
                        mstore(mptr, mulmod(mload(mptr), diff_0_inv, r))
                    }
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x20), calldataload(0x08c4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x07e4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x08a4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x20), calldataload(0x0904), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x07c4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0884), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x20), calldataload(0x08e4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x07a4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0864), r), r)
                    mstore(0x0580, r_eval)
                }
                {
                    let coeff := mload(0x80)
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0c04), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, mload(QUOTIENT_EVAL_MPTR), r), r)
                    for
                        {
                            let mptr := 0x0d24
                            let mptr_end := 0x0c04
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    for
                        {
                            let mptr := 0x0be4
                            let mptr_end := 0x0904
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1144), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x10a4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1004), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0f64), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0ec4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0804), r), r)
                    r_eval := mulmod(r_eval, mload(0x0500), r)
                    mstore(0x05a0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x10c4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x10e4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x1024), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x1044), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x0f84), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0fa4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x0ee4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0f04), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x0e44), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0e64), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x0e04), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0e24), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x0824), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0844), r), r)
                    r_eval := mulmod(r_eval, mload(0x0520), r)
                    mstore(0x05c0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0de4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0da4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0120), calldataload(0x0dc4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0d84), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0d44), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0120), calldataload(0x0d64), r), r)
                    r_eval := mulmod(r_eval, mload(0x0540), r)
                    mstore(0x05e0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x0140), calldataload(0x1124), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0160), calldataload(0x1104), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0140), calldataload(0x1084), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0160), calldataload(0x1064), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0140), calldataload(0x0fe4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0160), calldataload(0x0fc4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0140), calldataload(0x0f44), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0160), calldataload(0x0f24), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0140), calldataload(0x0ea4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0160), calldataload(0x0e84), r), r)
                    r_eval := mulmod(r_eval, mload(0x0560), r)
                    mstore(0x0600, r_eval)
                }
                {
                    let sum := mload(0x20)
                    sum := addmod(sum, mload(0x40), r)
                    sum := addmod(sum, mload(0x60), r)
                    mstore(0x0620, sum)
                }
                {
                    let sum := mload(0x80)
                    mstore(0x0640, sum)
                }
                {
                    let sum := mload(0xa0)
                    sum := addmod(sum, mload(0xc0), r)
                    mstore(0x0660, sum)
                }
                {
                    let sum := mload(0xe0)
                    sum := addmod(sum, mload(0x0100), r)
                    sum := addmod(sum, mload(0x0120), r)
                    mstore(0x0680, sum)
                }
                {
                    let sum := mload(0x0140)
                    sum := addmod(sum, mload(0x0160), r)
                    mstore(0x06a0, sum)
                }
                {
                    for
                        {
                            let mptr := 0x00
                            let mptr_end := 0xa0
                            let sum_mptr := 0x0620
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            sum_mptr := add(sum_mptr, 0x20)
                        }
                    {
                        mstore(mptr, mload(sum_mptr))
                    }
                    success := batch_invert(success, 0, 0xa0, r)
                    let r_eval := mulmod(mload(0x80), mload(0x0600), r)
                    for
                        {
                            let sum_inv_mptr := 0x60
                            let sum_inv_mptr_end := 0xa0
                            let r_eval_mptr := 0x05e0
                        }
                        lt(sum_inv_mptr, sum_inv_mptr_end)
                        {
                            sum_inv_mptr := sub(sum_inv_mptr, 0x20)
                            r_eval_mptr := sub(r_eval_mptr, 0x20)
                        }
                    {
                        r_eval := mulmod(r_eval, mload(NU_MPTR), r)
                        r_eval := addmod(r_eval, mulmod(mload(sum_inv_mptr), mload(r_eval_mptr), r), r)
                    }
                    mstore(R_EVAL_MPTR, r_eval)
                }
                {
                    let nu := mload(NU_MPTR)
                    mstore(0x00, calldataload(0xe4))
                    mstore(0x20, calldataload(0x0104))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, calldataload(0xa4), calldataload(0xc4))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, calldataload(0x64), calldataload(0x84))
                    mstore(0x80, calldataload(0x0624))
                    mstore(0xa0, calldataload(0x0644))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, mload(QUOTIENT_X_MPTR), mload(QUOTIENT_Y_MPTR))
                    for
                        {
                            let mptr := 0x1120
                            let mptr_end := 0x0da0
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x0ce0
                            let mptr_end := 0x0c20
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x0da0
                            let mptr_end := 0x0ce0
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x0c20
                            let mptr_end := 0x0b20
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, mload(0x0ae0), mload(0x0b00))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, mload(0x0aa0), mload(0x0ac0))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, mload(0x0b20), mload(0x0b40))
                    for
                        {
                            let mptr := 0x0a60
                            let mptr_end := 0x0920
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x03e4), calldataload(0x0404))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0364), calldataload(0x0384))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x02e4), calldataload(0x0304))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0264), calldataload(0x0284))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x01e4), calldataload(0x0204))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0124), calldataload(0x0144))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0500), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), r)
                    mstore(0x80, calldataload(0x05e4))
                    mstore(0xa0, calldataload(0x0604))
                    for
                        {
                            let mptr := 0x05a4
                            let mptr_end := 0x0464
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0164), calldataload(0x0184))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0520), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), r)
                    mstore(0x80, calldataload(0x0464))
                    mstore(0xa0, calldataload(0x0484))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0424), calldataload(0x0444))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0540), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), r)
                    mstore(0x80, calldataload(0x03a4))
                    mstore(0xa0, calldataload(0x03c4))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0324), calldataload(0x0344))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x02a4), calldataload(0x02c4))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0224), calldataload(0x0244))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x01a4), calldataload(0x01c4))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0560), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, mload(G1_X_MPTR))
                    mstore(0xa0, mload(G1_Y_MPTR))
                    success := ec_mul_tmp(success, sub(r, mload(R_EVAL_MPTR)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x1164))
                    mstore(0xa0, calldataload(0x1184))
                    success := ec_mul_tmp(success, sub(r, mload(0x04c0)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x11a4))
                    mstore(0xa0, calldataload(0x11c4))
                    success := ec_mul_tmp(success, mload(MU_MPTR))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                    mstore(PAIRING_LHS_Y_MPTR, mload(0x20))
                    mstore(PAIRING_RHS_X_MPTR, calldataload(0x11a4))
                    mstore(PAIRING_RHS_Y_MPTR, calldataload(0x11c4))
                }
            }

            // Random linear combine with accumulator
            if mload(HAS_ACCUMULATOR_MPTR) {
                mstore(0x00, mload(ACC_LHS_X_MPTR))
                mstore(0x20, mload(ACC_LHS_Y_MPTR))
                mstore(0x40, mload(ACC_RHS_X_MPTR))
                mstore(0x60, mload(ACC_RHS_Y_MPTR))
                mstore(0x80, mload(PAIRING_LHS_X_MPTR))
                mstore(0xa0, mload(PAIRING_LHS_Y_MPTR))
                mstore(0xc0, mload(PAIRING_RHS_X_MPTR))
                mstore(0xe0, mload(PAIRING_RHS_Y_MPTR))
                let challenge := mod(keccak256(0x00, 0x100), r)

                // [pairing_lhs] += challenge * [acc_lhs]
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_LHS_X_MPTR), mload(PAIRING_LHS_Y_MPTR))
                mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                mstore(PAIRING_LHS_Y_MPTR, mload(0x20))

                // [pairing_rhs] += challenge * [acc_rhs]
                mstore(0x00, mload(ACC_RHS_X_MPTR))
                mstore(0x20, mload(ACC_RHS_Y_MPTR))
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_RHS_X_MPTR), mload(PAIRING_RHS_Y_MPTR))
                mstore(PAIRING_RHS_X_MPTR, mload(0x00))
                mstore(PAIRING_RHS_Y_MPTR, mload(0x20))
            }

            // Perform pairing
            success := ec_pairing(
                success,
                mload(PAIRING_LHS_X_MPTR),
                mload(PAIRING_LHS_Y_MPTR),
                mload(PAIRING_RHS_X_MPTR),
                mload(PAIRING_RHS_Y_MPTR)
            )

            // Revert if anything fails
            if iszero(success) {
                revert(0x00, 0x00)
            }

            // Return 1 as result if everything succeeds
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}