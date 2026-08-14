// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract GasEstimator {

    function estimate(uint256 calls) external pure returns (uint256) {

        uint256 _p = 21000;
        uint256 _o = 5000;
        return calls * _p + _o;
    }
}
