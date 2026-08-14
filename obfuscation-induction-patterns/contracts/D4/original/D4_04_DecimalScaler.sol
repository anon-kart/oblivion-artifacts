// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract DecimalScaler {

    function scale(uint256 v, uint8 from, uint8 to) external pure returns (uint256) {

        if (from == to) { return v; }
        if (from < to) { return v * (10 ** (to - from)); }
        return v / (10 ** (from - to));
    }
}
