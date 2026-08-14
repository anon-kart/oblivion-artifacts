// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract DecimalScaler {

    function scale(uint256 v, uint8 from, uint8 to) external pure returns (uint256) {
        uint8 _f = from; uint8 _t = to;
        if (_f == _t) { return v; }
        if (_f < _t) { return v * (10 ** (_t - _f)); }
        return v / (10 ** (_f - _t));
    }
}
