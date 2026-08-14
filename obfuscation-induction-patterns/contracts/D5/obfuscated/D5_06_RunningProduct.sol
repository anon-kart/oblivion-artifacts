// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract RunningProduct {

    function product(uint256[] calldata xs) external pure returns (uint256) {

        uint256 p = 1; uint256 _f;
        for (uint256 _i = 0; _i < xs.length; _i++) {
            _f = xs[_i];
            p = p * _f;
        }
        return p;
    }
}
