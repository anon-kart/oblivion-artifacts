// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract ArraySum {

    function total(uint256[] calldata xs) external pure returns (uint256) {

        uint256 acc;
        uint256 _step;
        for (uint256 _i = 0; _i < xs.length; _i++) {
            _step = xs[_i];
            acc += _step;
        }
        return acc;
    }
}
