// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract CollateralRatio {

    function healthy(uint256 collateral, uint256 debt) external pure returns (bool) {

        if (debt == 0) { return true; }
        uint256 ratio = (collateral * 100) / debt;
        return ratio >= 150;
    }
}
