// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract MaxFinder {

    function largest(uint256[] calldata xs) external pure returns (uint256) {

        uint256 best;
        for (uint256 i = 0; i < xs.length; i++) {
            uint256 cur = xs[i];
            if (cur > best) { best = cur; }
        }
        return best;
    }
}
