// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract RangeChecksum {

    function checksum(uint256 from, uint256 to) external pure returns (uint256) {

        uint256 sum; uint256 _sq;
        for (uint256 _i = from; _i < to; _i++) {
            _sq = _i * _i;
            sum += _sq;
        }
        return sum;
    }
}
