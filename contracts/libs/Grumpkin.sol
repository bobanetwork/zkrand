// This file is MIT Licensed.
pragma solidity ^0.8.0;

library Grumpkin {
    struct Point {
        uint X;
        uint Y;
    }

    /// Check if point is valid.
    function isOnCurve(
            Point memory a
    ) internal view returns (bool) {
        uint r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

        // Y^2 = X^3 - 17
        uint y2 = mulmod(a.Y, a.Y, r);
        uint z = addmod(y2, 17, r);
        uint x2 = mulmod(a.X, a.X, r);
        uint x3 = mulmod(a.X, x2, r);

        return z == x3;
    }
}