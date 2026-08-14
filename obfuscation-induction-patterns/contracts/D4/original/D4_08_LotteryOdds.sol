// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract LotteryOdds {

    function share(uint256 tickets, uint256 pot) external pure returns (uint256) {

        uint256 denom = 1000000;
        uint256 weight = (tickets * denom) / 1000;
        return (pot * weight) / denom;
    }
}
