// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract CountAbove {

    function howMany(uint256[] calldata xs, uint256 bar) external pure returns (uint256) {

        uint256 n; bool _hit;
        for (uint256 _i = 0; _i < xs.length; _i++) {
            _hit = xs[_i] > bar;
            if (_hit) { n++; }
        }
        return n;
    }
}
