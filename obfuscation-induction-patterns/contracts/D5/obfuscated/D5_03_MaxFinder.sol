// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract MaxFinder {

    function largest(uint256[] calldata xs) external pure returns (uint256) {

        uint256 best; uint256 _cur;
        for (uint256 _i = 0; _i < xs.length; _i++) {
            _cur = xs[_i];
            if (_cur > best) { best = _cur; }
        }
        return best;
    }
}
