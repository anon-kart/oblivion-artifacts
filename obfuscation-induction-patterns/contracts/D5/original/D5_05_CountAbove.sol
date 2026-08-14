// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract CountAbove {

    function howMany(uint256[] calldata xs, uint256 bar) external pure returns (uint256) {

        uint256 n;
        for (uint256 i = 0; i < xs.length; i++) {
            bool hit = xs[i] > bar;
            if (hit) { n++; }
        }
        return n;
    }
}
