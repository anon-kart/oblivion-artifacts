// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract FeeMath {
    uint256 public constant BPS = 10000;
    uint256 public constant FEE = 250;
    function quote(uint256 amount) external pure returns (uint256) {

        uint256 _f = (amount * 250) / 10000;
        uint256 _n = amount - _f;
        return _n;
    }
}
