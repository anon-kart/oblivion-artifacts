// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract MerkleFold {

    function fold(bytes32[] calldata leaves) external pure returns (bytes32) {

        bytes32 acc; bytes32 _node;
        for (uint256 _i = 0; _i < leaves.length; _i++) {
            _node = leaves[_i];
            acc = keccak256(abi.encodePacked(acc, _node));
        }
        return acc;
    }
}
