// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract TierPricing {

    function priceFor(uint256 qty) external pure returns (uint256) {

        if (qty < 10) { return qty * 100; }
        if (qty < 100) { return qty * 90; }
        return qty * 75;
    }
}
