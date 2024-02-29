// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2VerifyingKey {
    constructor() {
        assembly {
            mstore(0x0000, 0x17240d3554346652f15d88a6c9d38975ef2b87ac7d8f9de9f631a12aa943e8d4) // vk_digest
            mstore(0x0020, 0x0000000000000000000000000000000000000000000000000000000000000029) // num_instances
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
            mstore(0x0220, 0x186282957db913abd99f91db59fe69922e95040603ef44c0bd7aa3adeef8f5ac) // neg_s_g2_x_1
            mstore(0x0240, 0x17944351223333f260ddc3b4af45191b856689eda9eab5cbcddbbe570ce860d2) // neg_s_g2_x_2
            mstore(0x0260, 0x06d971ff4a7467c3ec596ed6efc674572e32fd6f52b721f97e35b0b3d3546753) // neg_s_g2_y_1
            mstore(0x0280, 0x06ecdb9f9567f59ed2eee36e1e1d58797fd13cc97fafc2910f5e8a12f202fa9a) // neg_s_g2_y_2
            mstore(0x02a0, 0x015a63f503d1e0b0ae508f39d4b0125cc1d4924b4006b7c903e1c8fb481e34bc) // fixed_comms[0].x
            mstore(0x02c0, 0x1619bf2ba5be46de37d1a11021d27f88aafd09c38af3652c8a67181db4e8365f) // fixed_comms[0].y
            mstore(0x02e0, 0x10f87d164a4e7caf443f0e8d0f3ed933f2f70742d98c34d363374f3303fa12be) // fixed_comms[1].x
            mstore(0x0300, 0x2e773cc7564e15b04c8a0b04d8f0e7f86ca5b5dc450130e8ee608a7e3627ef0d) // fixed_comms[1].y
            mstore(0x0320, 0x1f0b06c6378638866fa2399d9b5004f98393f4e8cb4177756524521e36268ed3) // fixed_comms[2].x
            mstore(0x0340, 0x0b6256e4a1ffd2151b3960c57b758cb70b03830ceb10a5ae434beca0a24256e8) // fixed_comms[2].y
            mstore(0x0360, 0x0e6d6771ddfdbe0440135793aef940d644cbc8169f44f6a00187bffe2d837f93) // fixed_comms[3].x
            mstore(0x0380, 0x29902a76ee6cf1f7e0f80deb483b02b47ee473e3f707e9848d5c894165760d94) // fixed_comms[3].y
            mstore(0x03a0, 0x11ce1e94fc2b21964fa5855c6b1b7e16ad9543879cacf4d92b737897c728fb4e) // fixed_comms[4].x
            mstore(0x03c0, 0x2edfb7a75f7213b2566429a41fd01f2d92e5519f09653cb6099d8c851ccc57a7) // fixed_comms[4].y
            mstore(0x03e0, 0x2583e20cfcb09eef4d14c70a32d7ee3f2395dd6d8105cc60b3d83f437b628193) // fixed_comms[5].x
            mstore(0x0400, 0x150d88e573020c93d85e4b4ea46b02174794a6f0b02976dcfc6afc800f6a5ddf) // fixed_comms[5].y
            mstore(0x0420, 0x27208c9a5067d9961549001714e43a921cce53f5a6f89d6caedcd84cf0d12498) // fixed_comms[6].x
            mstore(0x0440, 0x214d00c5e2c2b1adcbecb252e043aacec40576d60f640029e6f2585ed8d20327) // fixed_comms[6].y
            mstore(0x0460, 0x1117fd76d578acf67b1ae6d84ac2da4c64e7ecba6129216a8f192fd0af6880c1) // fixed_comms[7].x
            mstore(0x0480, 0x15ab1be9f46032075fd355e5a0be678b767762ef36af3e35adc6a75922a459a1) // fixed_comms[7].y
            mstore(0x04a0, 0x2b3b60b3bfd8831052c4b8c93608b352c7adfc1290dc26b478929296e2be72df) // fixed_comms[8].x
            mstore(0x04c0, 0x2fbeeed4a26be6ce2e0fec65fe4742183ff4b418cd8c31708ba2be0dbe2614cb) // fixed_comms[8].y
            mstore(0x04e0, 0x081a1d562f38b857fb7e200bb455094a011510db9ac0352f4a01fee1674d134d) // fixed_comms[9].x
            mstore(0x0500, 0x19421a4d1ab26b52bd8d1826af0c406339c8a4859e24c56dd25a7d7a72632b40) // fixed_comms[9].y
            mstore(0x0520, 0x098055bc990ea7766dbcd9e68cab85424dbc1e35b475b828ac74bad04a0e4993) // fixed_comms[10].x
            mstore(0x0540, 0x2dff61482366aedf115b5620ecba51925967fd2b76f882535d3a8440bb9e632e) // fixed_comms[10].y
            mstore(0x0560, 0x2d9868444d8e9ad5c58b5e212113587bc43f126737578a44fe9b8d215d5c43c2) // fixed_comms[11].x
            mstore(0x0580, 0x0012cbbc9046fe9404991650a9c63bca2a73b9689d6b4a282d3ece593d2c6cae) // fixed_comms[11].y
            mstore(0x05a0, 0x0f059d7b9a666a241103db1d05aea1410cba06829b3b46a22860ba76b47bd0ec) // fixed_comms[12].x
            mstore(0x05c0, 0x1c9c07d7052a4fc0e76e542e158b8096e1135ac44a821f2da5a0bf70ad01b75d) // fixed_comms[12].y
            mstore(0x05e0, 0x0608dd727a1215cfbf413f08953de41c3e1a2b7647507460d8d362bba6b651c5) // fixed_comms[13].x
            mstore(0x0600, 0x0aaa6de27163435a96ba963ed9137db68c30659b0bf8840633b8c0d8bbdb0141) // fixed_comms[13].y
            mstore(0x0620, 0x04ff801f32581f277f2aae4181d3e93bd3c4193b2ffe8b8f5e5931525c423718) // fixed_comms[14].x
            mstore(0x0640, 0x0042b16de3cfc1cf463ff136bc2d3f66248fd89fd654dd059b9fdaf4b76fdb50) // fixed_comms[14].y
            mstore(0x0660, 0x089a5cb6aa54502bfa80e59fafedb6c10e00110611f5cc189d6c2b5401baed8e) // fixed_comms[15].x
            mstore(0x0680, 0x16a4ea8a619d3a0f6bbc9d49605c2cdb43a322184e157a9a0027cb579c6f871c) // fixed_comms[15].y
            mstore(0x06a0, 0x0a6f62b81b36a81586edaa6d0e55a6d378270c8aea7656cd0238b96e5dbb7163) // fixed_comms[16].x
            mstore(0x06c0, 0x2c2db13a19d75023acbbc5902dfd5aa040ab0afec46ebed8d5df72e73d198561) // fixed_comms[16].y
            mstore(0x06e0, 0x00d8df4cdb71c308286d438134b660afa40e4c30f1608b6aa8dad54e7ae963aa) // fixed_comms[17].x
            mstore(0x0700, 0x1d8938469e98f4c1fb4e3a9ec1e30d01d03cc4a34208ccb50f8d5d300629eff1) // fixed_comms[17].y
            mstore(0x0720, 0x1673597432376a56d73037c729141945f4bd0e361b560e3b43d996f76cff42a0) // fixed_comms[18].x
            mstore(0x0740, 0x0832375a6233a2be501d112701d534ac2a6853d5cfbc51968defa3247e066085) // fixed_comms[18].y
            mstore(0x0760, 0x1e7cbb45a4ff193db2341ee9256bad2d4d7b984e6f821ea18d1b9821498968cf) // fixed_comms[19].x
            mstore(0x0780, 0x18e185639be628118a845c85421a71f6c05d7e5a803b905556aa1c8eaa68c80e) // fixed_comms[19].y
            mstore(0x07a0, 0x0a121b65da8aed07cbbf9c681f69f7a78f3cf6d9534d6bc2b98e5eb97f2e21af) // fixed_comms[20].x
            mstore(0x07c0, 0x0620b79d7a12e2efc980cb8983c0e68a25117a3f1d4996c2f57572530640d003) // fixed_comms[20].y
            mstore(0x07e0, 0x12d18930ba9626fc8a9219558188bf16cf1260d219af6493c64b115079ddd66a) // fixed_comms[21].x
            mstore(0x0800, 0x2494df1b1c0b5579e7f0a733d17b6925f1eecd34ad87ec65bfeba230c177ae79) // fixed_comms[21].y
            mstore(0x0820, 0x149d90c52e4671ac396bee11f8e4e908bf19be8fed7125f8e715256123dc9b49) // fixed_comms[22].x
            mstore(0x0840, 0x0cf84b6bff53a6eb96fbf105f33436567ef2a850421c1b7857f0cff7415923ef) // fixed_comms[22].y
            mstore(0x0860, 0x025550bcf8533857c7079a70825951e531fa330caed09e8e8e7a37bc7a22e1b7) // permutation_comms[0].x
            mstore(0x0880, 0x09ee131b20a3d2d709be6e00b0815568545a16b075266c650b95145f7985c9a0) // permutation_comms[0].y
            mstore(0x08a0, 0x148f7e6b3d21cceddbbe409213c616fcd62655e30f179079b8dd83190ff3d0fe) // permutation_comms[1].x
            mstore(0x08c0, 0x1b1163d7a5986d063c89d4509058c0900dbf0e916d42f47caa5bbb84da6d2033) // permutation_comms[1].y
            mstore(0x08e0, 0x17508a3d4dc6890d3d4eb596a9244c02de01d426af2a9be6fab3b0bf756f6f8e) // permutation_comms[2].x
            mstore(0x0900, 0x0f2bc9c872b367dbe73dd1431342b63e9255db07e9220e9604530a57fba44095) // permutation_comms[2].y
            mstore(0x0920, 0x010c5c88d9fa4b78d4f4be6464f55bfbcd5c4272518e5d3387a940854116363a) // permutation_comms[3].x
            mstore(0x0940, 0x18fe6b40c9a02080d4818e9f448a43c85716631728abe61dda04a6010bdcb3b1) // permutation_comms[3].y
            mstore(0x0960, 0x1531e11371e745df21c3a9064638ad54ae6211ecf7d8f287c28cd51113434c5a) // permutation_comms[4].x
            mstore(0x0980, 0x03c08edbd454483d3165b5b9b45df20f9dd927653de0c95034f888ec7d81eedb) // permutation_comms[4].y
            mstore(0x09a0, 0x0404ad9666f806a8f53078602039f6b1d713ceee1e2ca8a22b21772452e864fa) // permutation_comms[5].x
            mstore(0x09c0, 0x12d561989e0f89973c3848ec78d68621288c67fff7afcabcd29107e803176d5f) // permutation_comms[5].y
            mstore(0x09e0, 0x2c45c709358a6492d9953984f0e8f12d1974942942942c41cc8b8b87bc0a3c4b) // permutation_comms[6].x
            mstore(0x0a00, 0x2ff385885eacdda2b47969b4b82a2bd56603506909a524a793b698d9fee04c20) // permutation_comms[6].y
            mstore(0x0a20, 0x13ab267051d6a77d28fee208708d3b7e8bb36637e441724a5cb96095ed50187a) // permutation_comms[7].x
            mstore(0x0a40, 0x262f5493e2aa9d750f56a70fa203b4658b7c9c058097abc6f205bc05941da0aa) // permutation_comms[7].y
            mstore(0x0a60, 0x01a7837e6470babb230978a3079af34e382588caaf1c0c791e81f37222798929) // permutation_comms[8].x
            mstore(0x0a80, 0x155c9bea95acf37b018196229c82254163940010ab902b96a4dcde67c6a99a6f) // permutation_comms[8].y

            return(0, 0x0aa0)
        }
    }
}