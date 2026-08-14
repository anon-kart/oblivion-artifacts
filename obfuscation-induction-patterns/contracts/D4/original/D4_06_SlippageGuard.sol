// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract SlippageGuard {

    function minOut(uint256 expected, uint256 toleranceBps) external pure returns (uint256) {

        uint256 slip = (expected * toleranceBps) / 10000;
        return expected - slip;
    }
}
