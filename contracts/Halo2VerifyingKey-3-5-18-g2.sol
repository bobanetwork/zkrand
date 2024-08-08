// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2VerifyingKey {
    constructor() {
        assembly {
            mstore(0x0000, 0x24263b6e13839a737c80384d888a8d8a5b4fc302fe0b152eace4d27d970408c7) // vk_digest
            mstore(0x0020, 0x0000000000000000000000000000000000000000000000000000000000000031) // num_instances
            mstore(0x0040, 0x0000000000000000000000000000000000000000000000000000000000000012) // k
            mstore(0x0060, 0x30644259cd94e7dd5045d7a27013b7fcd21c9e3b7fa75222e7bda49b729b0401) // n_inv
            mstore(0x0080, 0x0f60c8fe0414cb9379b2d39267945f6bd60d06a05216231b26a9fcf88ddbfebe) // omega
            mstore(0x00a0, 0x0e1165d221ab96da2bb4efe1b8fbf541b58d00917384a41bc6ab624d6d3e2b76) // omega_inv
            mstore(0x00c0, 0x15a9c33a6d34b8fb8e5c3ff61814ca50c878ed14bc17d9442cd5c127bf33fd6d) // omega_inv_to_l
            mstore(0x00e0, 0x0000000000000000000000000000000000000000000000000000000000000000) // has_accumulator
            mstore(0x0100, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
            mstore(0x0120, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limbs
            mstore(0x0140, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limb_bits
            mstore(0x0160, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
            mstore(0x0180, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
            mstore(0x01a0, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
            mstore(0x01c0, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
            mstore(0x01e0, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
            mstore(0x0200, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
            mstore(0x0220, 0x172aa93c41f16e1e04d62ac976a5d945f4be0acab990c6dc19ac4a7cf68bf77b) // neg_s_g2_x_1
            mstore(0x0240, 0x2ae0c8c3a090f7200ff398ee9845bbae8f8c1445ae7b632212775f60a0e21600) // neg_s_g2_x_2
            mstore(0x0260, 0x190fa476a5b352809ed41d7a0d7fe12b8f685e3c12a6d83855dba27aaf469643) // neg_s_g2_y_1
            mstore(0x0280, 0x1c0a500618907df9e4273d5181e31088deb1f05132de037cbfe73888f97f77c9) // neg_s_g2_y_2
            mstore(0x02a0, 0x1571f5c7630c9b40377fdeac6a9bff5aca849775e5c9bfdff28b0d56ab66fade) // fixed_comms[0].x
            mstore(0x02c0, 0x04454e034377ce9eada52b79758574a1f6bec4a5d1a9b1000bf4b37dfef9728f) // fixed_comms[0].y
            mstore(0x02e0, 0x22860facd1f6e926189502423c2c5a9574a029165785fb4e2d97c54842de79e2) // fixed_comms[1].x
            mstore(0x0300, 0x269c82dccd1cc0c1f7d1dde27af2b70bc816d55a85e5d34eda84ac59681fbfc7) // fixed_comms[1].y
            mstore(0x0320, 0x1cbd1d4cd3bdb00107674ea706ceff9326776fb1ab41022a4593c5ca64efdbc2) // fixed_comms[2].x
            mstore(0x0340, 0x270a52b9c04b62356222434c5f9ee2953bfa32074f4bede7e9771ad87f82c046) // fixed_comms[2].y
            mstore(0x0360, 0x10b16e23a89a9c782eb3ac24b339874870f2c28881ad9671f2808ca0ddf85f1a) // fixed_comms[3].x
            mstore(0x0380, 0x04284e3800e6694e3f463bba6768fa81edf44a1b43b6b14328c479fc9d0b3dd7) // fixed_comms[3].y
            mstore(0x03a0, 0x20cacc43aec4d41d72fd6692234c438dcc616fa1b2a531b509d338a2590134f9) // fixed_comms[4].x
            mstore(0x03c0, 0x0b233f76cc566c1ca836d32c1ebecd32cbcd5bae9f6ac940e3b5bf93a3b238f5) // fixed_comms[4].y
            mstore(0x03e0, 0x26e82a20748fe704a6eb502be134800d27a51fb6ec86b310daa2302371ef875b) // fixed_comms[5].x
            mstore(0x0400, 0x0981fcfe54baac54439ccd0299d93a8e50a235bcf96ed527f23fde221023d544) // fixed_comms[5].y
            mstore(0x0420, 0x206497f656d155232b89a1dcdc84f741c8fdf992657ff6668e6003e250525ba2) // fixed_comms[6].x
            mstore(0x0440, 0x1ac410f4cf9aac1639f2d6ce154916094594813a8e9b81124b8262ecc3c06329) // fixed_comms[6].y
            mstore(0x0460, 0x244b7b52a4be237bbeb91bc1be40326bd38ff6611cc7a87d21e4755dbb27d97a) // fixed_comms[7].x
            mstore(0x0480, 0x280a58227ce85bb0465f4f24e0b76289a1529a4fee22428da6e19314ddf3bc81) // fixed_comms[7].y
            mstore(0x04a0, 0x14ab595121038bfe0cd450ffa868a2a36ff407820765da008e20127d9f08e12b) // fixed_comms[8].x
            mstore(0x04c0, 0x0f1c302bf83dea269b9b686797d4988ccfaad883adf0d0116be45459b30745fc) // fixed_comms[8].y
            mstore(0x04e0, 0x1534d762affa5f34b85c0c841a444b2eab2ff9be27abf422c0a067563b61ad8e) // fixed_comms[9].x
            mstore(0x0500, 0x097c4118763f9f91fc7fe4d599e15ca1c853634dda944a43ad20fde87e1437d8) // fixed_comms[9].y
            mstore(0x0520, 0x06a03d24a14f4c30d9d9bc40538922a71796220be15fb7202c6bb50fc25a54aa) // fixed_comms[10].x
            mstore(0x0540, 0x123f19e843116be66fd91d9f7f928eba8e3902282cc6aeed000964df6d907ef9) // fixed_comms[10].y
            mstore(0x0560, 0x078d5c66cdaa21420776783334a04be2a75e29bf70668fb608e771ebdab0abee) // fixed_comms[11].x
            mstore(0x0580, 0x24b79cf62d3c738630d490fdfd4295083763cc86ffc038bae237e21371318366) // fixed_comms[11].y
            mstore(0x05a0, 0x2ed84487ed99478152b46e48924affeb37ccb6feb966876d764c442ccffd7ee4) // fixed_comms[12].x
            mstore(0x05c0, 0x28598da0148d15a389da39c32f42aedc5e605524a213c67ba7f7441495af9770) // fixed_comms[12].y
            mstore(0x05e0, 0x163f8a58698269e283c0c2b4170d2fe74497526bf8a592d281d772d6c36c99cd) // fixed_comms[13].x
            mstore(0x0600, 0x0f4a8b7fe003a579692b534a2d8c218c67006834cafb8f1029f64f986e6ab7ad) // fixed_comms[13].y
            mstore(0x0620, 0x0cd536d8fc67ecb3da4cb6db58ff25f68aa55c021cb5aaadbdec798f13f793c4) // fixed_comms[14].x
            mstore(0x0640, 0x1f5a77a7784707a5a28c0c4c9432611085cf93ef5d37ba9b395f396dc81f833a) // fixed_comms[14].y
            mstore(0x0660, 0x2ac6e14d310b276367d61cf2a4d5d5297e0664b97f21bf8a4958a41051a11842) // fixed_comms[15].x
            mstore(0x0680, 0x2670a3c7944956289cfb895083c3a3659784dce1ba581ee657d9a8021b4f5ffb) // fixed_comms[15].y
            mstore(0x06a0, 0x1d9009e841c6e5129d052701b76ffd481b3a3bc21ee7a17383106fa5f10f7c03) // fixed_comms[16].x
            mstore(0x06c0, 0x2dee49d7e29188dbdf7eed039cf77b0511ab6cc5e611e9e4d3a696d41f9da25c) // fixed_comms[16].y
            mstore(0x06e0, 0x010cd824cd8ec841e3e1cceb23fa9cb5f3d227785a3b64531f75d10482bb1cf8) // fixed_comms[17].x
            mstore(0x0700, 0x14b812a905aa89e14196b47dc52af6904293822e9a77176af599668813291273) // fixed_comms[17].y
            mstore(0x0720, 0x1e9c6118c7e219e8cdfd7594762dd482024bf55c9c1539275ac7780ee94b8418) // fixed_comms[18].x
            mstore(0x0740, 0x2dedd8e9074bc0b4413693915077a4d27a48e56dbe4b1f1ecaff5e6b46c4a70f) // fixed_comms[18].y
            mstore(0x0760, 0x23ac44d545cdbfcb9d443ef507cad01729b015451088118caa0bd84ab4668d78) // fixed_comms[19].x
            mstore(0x0780, 0x1fa9065b8741f55582a68bb3a4d61d57dd530240bbf2c25e9725da038384251f) // fixed_comms[19].y
            mstore(0x07a0, 0x0758771c463147b118f3af1a369b2c55741d49db71a41552b7f2871b17b6cbe2) // fixed_comms[20].x
            mstore(0x07c0, 0x235e8a8bccb5f289733880f2de5257e8451d2579abedff3cc06c862bfb1d6cef) // fixed_comms[20].y
            mstore(0x07e0, 0x015eab43a9f4d71980590c9583325ca562ffcea2890e35420fa12d54f701da8b) // fixed_comms[21].x
            mstore(0x0800, 0x2526668d07cb0c169108c09e1ec84e45f2f83c5b741f624e194ef02849f4fd09) // fixed_comms[21].y
            mstore(0x0820, 0x01eb56f799af469b397c6110a5950682a636b163542ddabf0be4bb90bdf74b0f) // fixed_comms[22].x
            mstore(0x0840, 0x2aabd6b6f8bb5bc4d8bfe2d77e07f2b144bc09b428a9bf6c1aecbb41c9bf2f77) // fixed_comms[22].y
            mstore(0x0860, 0x2b0f4175273f10bf767b57c7512bb8f2b4c43d59bccf07bde991d21a69f35913) // permutation_comms[0].x
            mstore(0x0880, 0x05816fe8a870114ac4e376c3f6d10d29a804f34b1a4320430534d25cbfc3cde9) // permutation_comms[0].y
            mstore(0x08a0, 0x24aa773c2969e17a0a14af06dbf184489eeaadb7b43d82d00fb8a3528771f6af) // permutation_comms[1].x
            mstore(0x08c0, 0x02738c2b989544b730655326b560f705aa5b4291de9541a6f17cb3a61736991c) // permutation_comms[1].y
            mstore(0x08e0, 0x28184c7a4e97fd82723b7019eca047c6110d4d8b7d70e89fa0d2181620ef11df) // permutation_comms[2].x
            mstore(0x0900, 0x283ef06e680a9473ea2b419cccd998b3e69bb119a785fd07305583e4e9cb23de) // permutation_comms[2].y
            mstore(0x0920, 0x0873dddca010747e3ea5a4d9f9166de3dacf9a307677e2a5ce2d0c6294c7add8) // permutation_comms[3].x
            mstore(0x0940, 0x0347050b6661e055310c145ba744e759d2311c55e6a36327bb9746914b4e54a9) // permutation_comms[3].y
            mstore(0x0960, 0x252b866ca945e61d7dc25845bc910600bd4150192e1eafc9ddfb561009bf5b66) // permutation_comms[4].x
            mstore(0x0980, 0x04270813f2190ffc50395ece5dc408e81e5542569b81ff50f254d75d8cb14dfb) // permutation_comms[4].y
            mstore(0x09a0, 0x0b90b2bd42341870d0e824692904fe9e0f0a1154e3c0d45d973a1c39ac14e91e) // permutation_comms[5].x
            mstore(0x09c0, 0x050832d6b790573a4b050f220fcbd0b485d5f05b88fc6005ad6cec372f4f3e9a) // permutation_comms[5].y
            mstore(0x09e0, 0x19667763c031ec5db9ceeda538a2f838ef3e86fd55916bc351a448085e79095c) // permutation_comms[6].x
            mstore(0x0a00, 0x07d67946527f49e4011475b4ac1ec33f2ee13edbbe68a5cd6b8ea12d22c93538) // permutation_comms[6].y
            mstore(0x0a20, 0x05fcc65042dcfe4b5219f973d97a5c47a183c364ada63fa9cd64801df9af4a03) // permutation_comms[7].x
            mstore(0x0a40, 0x06b7d26a40848c5a04eb52dc54c826fb34e7e9d57826d454efd213bebf20c994) // permutation_comms[7].y
            mstore(0x0a60, 0x2d0907a38fb7970289a839670c23458478994c2e3b6ffcf2bceebb3207d039f3) // permutation_comms[8].x
            mstore(0x0a80, 0x0665a7d46d31912dfc39276edff88bf8b8418739c08cd3b2d93a159dce3e1a84) // permutation_comms[8].y

            return(0, 0x0aa0)
        }
    }
}