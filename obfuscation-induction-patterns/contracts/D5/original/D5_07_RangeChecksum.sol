// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract RangeChecksum {

    function checksum(uint256 from, uint256 to) external pure returns (uint256) {

        uint256 sum;
        for (uint256 i = from; i < to; i++) {
            uint256 sq = i * i;
            sum += sq;
        }
        return sum;
    }
}
