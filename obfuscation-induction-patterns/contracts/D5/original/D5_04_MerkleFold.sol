// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract MerkleFold {

    function fold(bytes32[] calldata leaves) external pure returns (bytes32) {

        bytes32 acc;
        for (uint256 i = 0; i < leaves.length; i++) {
            bytes32 node = leaves[i];
            acc = keccak256(abi.encodePacked(acc, node));
        }
        return acc;
    }
}
