// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract LotteryOdds {

    function share(uint256 tickets, uint256 pot) external pure returns (uint256) {

        uint256 _d = 1000000;
        uint256 _w = (tickets * _d) / 1000;
        return (pot * _w) / _d;
    }
}
