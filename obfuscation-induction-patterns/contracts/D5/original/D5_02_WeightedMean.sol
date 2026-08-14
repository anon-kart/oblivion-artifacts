// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract WeightedMean {

    function mean(uint256[] calldata v, uint256[] calldata w) external pure returns (uint256) {

        uint256 num; uint256 den;
        for (uint256 i = 0; i < v.length; i++) {
            uint256 term = v[i] * w[i];
            num += term; den += w[i];
        }
        return den == 0 ? 0 : num / den;
    }
}
