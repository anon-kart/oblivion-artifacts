// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract InterestAccrual {
    uint256 public constant SECONDS_PER_YEAR = 31536000;
    function accrue(uint256 principal, uint256 elapsed) external pure returns (uint256) {

        uint256 _r = 500;
        uint256 _i = (principal * _r * elapsed) / (10000 * 31536000);
        return principal + _i;
    }
}
