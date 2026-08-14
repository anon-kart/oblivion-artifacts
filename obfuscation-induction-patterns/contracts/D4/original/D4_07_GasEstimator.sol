// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract GasEstimator {

    function estimate(uint256 calls) external pure returns (uint256) {

        uint256 perCall = 21000;
        uint256 overhead = 5000;
        return calls * perCall + overhead;
    }
}
