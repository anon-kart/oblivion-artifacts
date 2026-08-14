// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract RewardCurve {

    function reward(uint256 day) external pure returns (uint256) {

        uint256 halvings = day / 1460;
        uint256 base = 50;
        return base >> halvings;
    }
}
