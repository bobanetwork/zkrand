// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2VerifyingKey {
    constructor() {
        assembly {
            mstore(0x0000, 0x28f484b8e38cdbda30a10af8ebbb41e5e707105e86f1a0f965f61865847076d6) // vk_digest
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
            mstore(0x0220, 0x186282957db913abd99f91db59fe69922e95040603ef44c0bd7aa3adeef8f5ac) // neg_s_g2_x_1
            mstore(0x0240, 0x17944351223333f260ddc3b4af45191b856689eda9eab5cbcddbbe570ce860d2) // neg_s_g2_x_2
            mstore(0x0260, 0x06d971ff4a7467c3ec596ed6efc674572e32fd6f52b721f97e35b0b3d3546753) // neg_s_g2_y_1
            mstore(0x0280, 0x06ecdb9f9567f59ed2eee36e1e1d58797fd13cc97fafc2910f5e8a12f202fa9a) // neg_s_g2_y_2
            mstore(0x02a0, 0x05eb072e2e25be4cd57050b2479563a8cab0a33474a26873ae63c927995aa6ae) // fixed_comms[0].x
            mstore(0x02c0, 0x2f9b4b6b6255f64ccc8b47e0a2bc12a205428ae623f499fb424f33570845dd36) // fixed_comms[0].y
            mstore(0x02e0, 0x189f7e8a01397ea94d60fde3c1d011691522b5346704df4aef2545ef01d08c3b) // fixed_comms[1].x
            mstore(0x0300, 0x203196b23e9abf6bbf25739404084c9fbcf74472aa85afb3c2fe0fd663b1beb5) // fixed_comms[1].y
            mstore(0x0320, 0x0fa049ad36cdfc60f60e0191a48b4e9f847d5bbb4f23a266d107c91daf4e372d) // fixed_comms[2].x
            mstore(0x0340, 0x1639428cf4875e46ba50588b9bbf46ce90e7a427581aef099d784efe05b93cb3) // fixed_comms[2].y
            mstore(0x0360, 0x1db0ac7bfaea513a6540a0eb99711d1bb5842656d18d1e6ca6b152d86c683cea) // fixed_comms[3].x
            mstore(0x0380, 0x2bf00d4d4000b1d5318f9e6d640bcffb1dd730f42241f563f0be99383a8d4145) // fixed_comms[3].y
            mstore(0x03a0, 0x23675493f72c7cb1991b68110ff45c0609dbb75996995a3518c0e8e869606083) // fixed_comms[4].x
            mstore(0x03c0, 0x0d9978f391afee252992a7ab050e5c90e3feefe0d25409880a9cbe40bfa0d728) // fixed_comms[4].y
            mstore(0x03e0, 0x1b056c80ba2e49492e168276b113067272ae65e00513aad90b8a5a045364aae9) // fixed_comms[5].x
            mstore(0x0400, 0x0beb8cc57c02c565ce9645ae3cac718983d03de9a27bb8d1822a5829c591be6c) // fixed_comms[5].y
            mstore(0x0420, 0x1eb3a757059c7c2be4d1565e750a53bdac346f2bf3acd1b1d9f3e42d2dfadb3d) // fixed_comms[6].x
            mstore(0x0440, 0x172d7b846542f86e0f285fb9d6c9ecdd682746e4ea61c0715d7e91346c71f11d) // fixed_comms[6].y
            mstore(0x0460, 0x2df72f0703821c3aba995e0bd010703a389f80a23a2870e817d13dfa1779779a) // fixed_comms[7].x
            mstore(0x0480, 0x0d6e18412c38631db01a1e0b2529798a3da672bb238c80a60b9db371a068616e) // fixed_comms[7].y
            mstore(0x04a0, 0x143ee6d7d3ac176207e54b9bb293879045e7f06efbeabcdabf178123b81b167c) // fixed_comms[8].x
            mstore(0x04c0, 0x0982b69f805c16991ad606fe005cddcd756668993d23dc6939ec3dcfa6edce2d) // fixed_comms[8].y
            mstore(0x04e0, 0x081a1d562f38b857fb7e200bb455094a011510db9ac0352f4a01fee1674d134d) // fixed_comms[9].x
            mstore(0x0500, 0x19421a4d1ab26b52bd8d1826af0c406339c8a4859e24c56dd25a7d7a72632b40) // fixed_comms[9].y
            mstore(0x0520, 0x098055bc990ea7766dbcd9e68cab85424dbc1e35b475b828ac74bad04a0e4993) // fixed_comms[10].x
            mstore(0x0540, 0x2dff61482366aedf115b5620ecba51925967fd2b76f882535d3a8440bb9e632e) // fixed_comms[10].y
            mstore(0x0560, 0x2016f7f2c8a1037db9ec20e05dac5a3ab01050f50a3027574921074097d82ce6) // fixed_comms[11].x
            mstore(0x0580, 0x09db885711903280e326733335e89f86fccee1658e39094fa57592f2d24fb171) // fixed_comms[11].y
            mstore(0x05a0, 0x2f35e2101fb85e89e1d759ba971caa126954e293132416689f12f230a40a3bb4) // fixed_comms[12].x
            mstore(0x05c0, 0x1209c7e542e7a230dbe20c157baacba7c28fcc0aea9aef328df79a9db677078f) // fixed_comms[12].y
            mstore(0x05e0, 0x1af95d0cfad6dc54ccf7f4eee74aa57a58ba0a2e0cc60a215691dfa3879b373c) // fixed_comms[13].x
            mstore(0x0600, 0x214d6e7644ce1d2057bd2ad4d1bf86cc126e5c07d366e96f7b9405efa74155e2) // fixed_comms[13].y
            mstore(0x0620, 0x2f3a4c970d966e28ee4e4ddc33e2c724e184266eb946f778aa89a385d97d5360) // fixed_comms[14].x
            mstore(0x0640, 0x1e3863e0433a4f27be02a700fe3f7505ea9b29f283e370c6f6629dff348d9d02) // fixed_comms[14].y
            mstore(0x0660, 0x118e811b4f633ea7348d7bbbf6e5044591c73aa85468b97e09be5e9ecaf0550b) // fixed_comms[15].x
            mstore(0x0680, 0x1df89de9194a38a5d2173fd86caaef04c2919c0c9faec2e9fdce03142b861dc7) // fixed_comms[15].y
            mstore(0x06a0, 0x12cb83ada9f9120853b59ea7971dba8bd30ce170187575e81ae0743334b269f0) // fixed_comms[16].x
            mstore(0x06c0, 0x2f9c5b12fedf34efc451e3ff8344d2e58c66c656a4fb38069af2cc89d6699f09) // fixed_comms[16].y
            mstore(0x06e0, 0x1a8c4ebfcba32af38c02e59235886ac12164cd573359b99aaca8c7f6896cf70a) // fixed_comms[17].x
            mstore(0x0700, 0x29aec80f63f58bb0faf447e6fc8400a68aeaf3469ba28123523782f2f82bc9d9) // fixed_comms[17].y
            mstore(0x0720, 0x042105d74438a95d3e9dfc6d3fef7dcb850478184e38bc23241a06b2e83b0886) // fixed_comms[18].x
            mstore(0x0740, 0x18d31e7bca6a9dcf2101086dc68fc0789f5e794064957809f302b4fe5518fd04) // fixed_comms[18].y
            mstore(0x0760, 0x0469cf9a28695cf4230e884c3d866b9eebc717da5000d2c0bbfa727e19bfb5bc) // fixed_comms[19].x
            mstore(0x0780, 0x28cb90afe58474ae587e422e0f1d1e65e518af567ed3f837258d97f2fd417ed5) // fixed_comms[19].y
            mstore(0x07a0, 0x0a74d96d6d81255eacde6623799f50288c7f40635e6b466b73869fd67b7b9c68) // fixed_comms[20].x
            mstore(0x07c0, 0x23c98458690ab8999d017f0fa1ccae390013977d9e82e36f9a45bc0b62c181e5) // fixed_comms[20].y
            mstore(0x07e0, 0x2b299b627e8ba7e8505ef39eb9f3de3399487f0b501c48af89d0c5384789894f) // fixed_comms[21].x
            mstore(0x0800, 0x0aaca08094f1b0f00afae4cd40085a266c5dbfdf028d08d0045a3f0bbd108213) // fixed_comms[21].y
            mstore(0x0820, 0x082eee13998b0eab15f47654a2a1dd1f087b4488181ff583aed6e31f09b0d84f) // fixed_comms[22].x
            mstore(0x0840, 0x2df0468511a9a9ea67280eb7fd5b13563d6523b0b2cbfed93a1a107c090d0179) // fixed_comms[22].y
            mstore(0x0860, 0x107f9b4031048405cf7fe79f479aa7d034ed5ee476bac3d2883d9cf590f32f36) // permutation_comms[0].x
            mstore(0x0880, 0x1fd1d5e6962addf04a6c7a41d1f285f74a63e0cdc7ef3d566f924ec65b26c216) // permutation_comms[0].y
            mstore(0x08a0, 0x290c6d652d0feebe6e5134951efc8f91f098603db59ccdf1c71790001bf475e9) // permutation_comms[1].x
            mstore(0x08c0, 0x04a8c6f2a650e8c1af9271dfce5d4e2c47cf84fa5deab2bbabfc0da1500f7aa5) // permutation_comms[1].y
            mstore(0x08e0, 0x20d821cae9011a22b46601119b2850b7cb1e6022d2177b90704d7d0d4824fa9d) // permutation_comms[2].x
            mstore(0x0900, 0x1b0dc4704aefde1f077e4291a6e7fefad8f1d68113f17a39561333b094f80828) // permutation_comms[2].y
            mstore(0x0920, 0x2dbf71560e208ebfdcafba5948af4daf13eccaa4946e8980355a70f6a88939e5) // permutation_comms[3].x
            mstore(0x0940, 0x0a59ab9e6f9e38ece0fcf671e86a100756e9dcebd57e9e248117c396c748f8ac) // permutation_comms[3].y
            mstore(0x0960, 0x19176750d0598f78083d4ab19cacd9d04d6adaa8eeef06fd3ab7b79a607c5bfe) // permutation_comms[4].x
            mstore(0x0980, 0x05621c33df32e7fabac1205f2e6646b0f647fbe3c36c18c39a8b305909a46e1e) // permutation_comms[4].y
            mstore(0x09a0, 0x1b33185590dc0c788bcece4805839c555dae54f38f3f0ce6aa1056fb1156cd7c) // permutation_comms[5].x
            mstore(0x09c0, 0x0f5f1df59253d748d42a6810fb47c4100e9ed6179c231d8199f37680626a0183) // permutation_comms[5].y
            mstore(0x09e0, 0x0bfac06910eaf9aeca38a84550d36e5432ea90b47060a078e4f98cf608bc566e) // permutation_comms[6].x
            mstore(0x0a00, 0x0355eecc37b6bed24f95964c0089a4f3a86669c78ad2b99dd1ac8f19407cfabd) // permutation_comms[6].y
            mstore(0x0a20, 0x13ab267051d6a77d28fee208708d3b7e8bb36637e441724a5cb96095ed50187a) // permutation_comms[7].x
            mstore(0x0a40, 0x262f5493e2aa9d750f56a70fa203b4658b7c9c058097abc6f205bc05941da0aa) // permutation_comms[7].y
            mstore(0x0a60, 0x01a7837e6470babb230978a3079af34e382588caaf1c0c791e81f37222798929) // permutation_comms[8].x
            mstore(0x0a80, 0x155c9bea95acf37b018196229c82254163940010ab902b96a4dcde67c6a99a6f) // permutation_comms[8].y

            return(0, 0x0aa0)
        }
    }
}