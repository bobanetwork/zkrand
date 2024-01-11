pragma solidity ^0.8.0;

import {Pairing} from "./Pairing.sol";
import {ModexpInverse, ModexpSqrt} from "./ModExp.sol";

library Hash {
    // BN254 base field
    uint public constant Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    // q-1
    uint public constant MINUS_ONE = 21888242871839275222246405745257275088696311157297823662689037894645226208582;
    // (q-1)/2
    uint public constant Q2 = 10944121435919637611123202872628637544348155578648911831344518947322613104291;
    // 2^256 mod Q
    uint public constant R = 6350874878119819312338956282401532409788428879151445726012394534686998597021;
    // (-1 + sqrt(-3))/2
    uint public constant C1 = 2203960485148121921418603742825762020974279258880205651966;
    // sqrt(-3)
    uint public constant C2 = 4407920970296243842837207485651524041948558517760411303933;
    // 1/3
    uint public constant C3 = 14592161914559516814830937163504850059130874104865215775126025263096817472389;
    // g(1) = 1^3 + b
   // uint public constant C4 = 4;

    function sqrt(uint a) internal view returns (uint r, bool exist) {
        r = ModexpSqrt.run(a);
        exist = mulmod(r, r, Q) == a;
    }

    function sign(uint t) internal view returns (bool) {
        if (t <= Q2) {
            return true;
        } else {
            return false;
        }
    }

    // https://eips.ethereum.org/EIPS/eip-3068 (with error in constant2)
    // Fouque and Tibouchi https://eips.ethereum.org/assets/eip-3068/latincrypt12.pdf
    // Wahby and Boneh https://eips.ethereum.org/assets/eip-3068/2019-403_BLS12_H2C.pdf (for replacing sqrt(t) with sign(t))
    function hashToField(bytes memory domain, bytes memory message) internal view returns (uint[2] memory) {
        uint domain_len = domain.length;
        uint msg_len = message.length;

        bytes memory input = abi.encodePacked(bytes1(0x00), bytes1(0x01), domain_len, domain, msg_len, message);
        bytes32 hash0 = keccak256(input);
        bytes32 hash1 = keccak256(abi.encodePacked(bytes1(0x02), bytes1(0x03), hash0));
        bytes32 hash2 = keccak256(abi.encodePacked(bytes1(0x04), bytes1(0x05), hash1));
        bytes32 hash3 = keccak256(abi.encodePacked(bytes1(0x06), bytes1(0x07), hash2));

        uint t0 = uint(hash0);
        uint t1 = uint(hash1);
        uint f1 = mulmod(t0, R, Q);
        f1 = addmod(f1, t1, Q);

        uint t2 = uint(hash2);
        uint t3 = uint(hash3);
        uint f2 = mulmod(t2, R, Q);
        f2 = addmod(f2, t3, Q);

        return [f1, f2];
    }


    function mapToG1(uint t) internal view returns (Pairing.G1Point memory) {
        require(t < Q, "mapToG1 failed: invalid field element");
        // c1 = (-1 + sqrt(-3))/2
        // c2 = sqrt(-3)
        // c3 = 1/3
        // s = (t^2 + 4)^3
        // alpha = 1/(t^2 * (t^2 + 4))
        // x1 = C1 - C2 * t^4 * alpha
        // x2 = -1 - x1
        // x3 = 1 - s * alpha/3
        bool t_sign = sign(t);
        uint t_square = mulmod(t, t, Q);
        uint t4 = mulmod(t_square, t_square, Q);
        uint r = addmod(t_square, 4, Q);
        uint r_square = mulmod(r, r, Q);
        uint s = mulmod(r, r_square, Q);

        uint alpha = mulmod(t_square, r, Q);
        alpha = ModexpInverse.run(alpha);

        uint x1 = mulmod(t4, alpha, Q);
        x1 = mulmod(C2, x1, Q);
        x1 = Q - x1;
        x1 = addmod(C1, x1, Q);

        // a = x1^3 + b
        {
            uint a = mulmod(x1, x1, Q);
            a = mulmod(a, x1, Q);
            a = addmod(a, 3, Q);
            (uint y, bool exist) = sqrt(a);
            if (exist) {
                if (!t_sign) {
                    y = Q - y;
                }
                return Pairing.G1Point(x1,y);
            }
        }

        uint x2 = addmod(x1, 1, Q);
        x2 = Q - x2;
        {
            uint a = mulmod(x2, x2, Q);
            a = mulmod(a, x2, Q);
            a = addmod(a, 3, Q);
            (uint y, bool exist) = sqrt(a);
            if (exist) {
                if (!t_sign) {
                    y = Q - y;
                }
                return Pairing.G1Point(x2, y);
            }

        }

        uint x3 = mulmod(s, alpha, Q);
        x3 = mulmod(x3, C3, Q);
        x3 = Q - x3;
        x3 = addmod(x3, 1, Q);
        {
            uint a = mulmod(x3, x3, Q);
            a = mulmod(a, x3, Q);
            a = addmod(a, 3, Q);
            (uint y, bool exist) = sqrt(a);
            require(exist, "map to point failed");
            if (!t_sign) {
               y = Q - y;
            }
            return Pairing.G1Point(x3, y);
        }
    }


    function hashToG1(bytes memory domain, bytes memory message) internal view returns (Pairing.G1Point memory) {
        uint[2] memory f = hashToField(domain, message);
        Pairing.G1Point memory g = mapToG1(f[0]);
        Pairing.G1Point memory h = mapToG1(f[1]);
        g = Pairing.addition(g, h);
        return g;
    }
}