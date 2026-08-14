// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract RunningProduct {

    function product(uint256[] calldata xs) external pure returns (uint256) {

        uint256 p = 1;
        for (uint256 i = 0; i < xs.length; i++) {
            uint256 f = xs[i];
            p = p * f;
        }
        return p;
    }
}
