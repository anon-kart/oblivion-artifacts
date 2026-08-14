// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {MerkleFold as ORIG_MerkleFold} from "../contracts/D5/original/D5_04_MerkleFold.sol";
import {MerkleFold as OBF_MerkleFold} from "../contracts/D5/obfuscated/D5_04_MerkleFold.sol";

contract D5_MerkleFold_Oracle is Test {
    function test_D5_04_MerkleFold() public {
        ORIG_MerkleFold o = new ORIG_MerkleFold();
        OBF_MerkleFold b = new OBF_MerkleFold();
        bytes32[] memory ls = new bytes32[](3);
        ls[0] = keccak256("a"); ls[1] = keccak256("b"); ls[2] = keccak256("c");
        assertEq(o.fold(ls), b.fold(ls), "obfuscated output diverges from original");
    }
}
