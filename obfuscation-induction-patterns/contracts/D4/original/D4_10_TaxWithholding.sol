// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract TaxWithholding {

    function withhold(uint256 gross) external pure returns (uint256) {

        uint256 bracket1 = (gross * 10) / 100;
        uint256 bracket2 = gross > 1000 ? ((gross - 1000) * 20) / 100 : 0;
        return gross - bracket1 - bracket2;
    }
}
