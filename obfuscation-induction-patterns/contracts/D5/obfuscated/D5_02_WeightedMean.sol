// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract WeightedMean {

    function mean(uint256[] calldata v, uint256[] calldata w) external pure returns (uint256) {

        uint256 num; uint256 den; uint256 _term;
        for (uint256 _i = 0; _i < v.length; _i++) {
            _term = v[_i] * w[_i];
            num += _term; den += w[_i];
        }
        return den == 0 ? 0 : num / den;
    }
}
