// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract ArraySum {

    function total(uint256[] calldata xs) external pure returns (uint256) {

        uint256 acc;
        for (uint256 i = 0; i < xs.length; i++) {
            uint256 step = xs[i];
            acc += step;
        }
        return acc;
    }
}
