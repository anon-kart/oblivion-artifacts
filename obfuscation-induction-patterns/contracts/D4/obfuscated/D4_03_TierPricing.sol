// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract TierPricing {

    function priceFor(uint256 qty) external pure returns (uint256) {
        uint256 _q = qty;
        if (_q < 10) { return _q * 100; }
        if (_q < 100) { return _q * 90; }
        return _q * 75;
    }
}
