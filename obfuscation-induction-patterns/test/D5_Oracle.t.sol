// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {ArraySum as ORIG_ArraySum} from "../contracts/D5/original/D5_01_ArraySum.sol";
import {ArraySum as OBF_ArraySum} from "../contracts/D5/obfuscated/D5_01_ArraySum.sol";
import {WeightedMean as ORIG_WeightedMean} from "../contracts/D5/original/D5_02_WeightedMean.sol";
import {WeightedMean as OBF_WeightedMean} from "../contracts/D5/obfuscated/D5_02_WeightedMean.sol";
import {MaxFinder as ORIG_MaxFinder} from "../contracts/D5/original/D5_03_MaxFinder.sol";
import {MaxFinder as OBF_MaxFinder} from "../contracts/D5/obfuscated/D5_03_MaxFinder.sol";
import {CountAbove as ORIG_CountAbove} from "../contracts/D5/original/D5_05_CountAbove.sol";
import {CountAbove as OBF_CountAbove} from "../contracts/D5/obfuscated/D5_05_CountAbove.sol";
import {RunningProduct as ORIG_RunningProduct} from "../contracts/D5/original/D5_06_RunningProduct.sol";
import {RunningProduct as OBF_RunningProduct} from "../contracts/D5/obfuscated/D5_06_RunningProduct.sol";
import {RangeChecksum as ORIG_RangeChecksum} from "../contracts/D5/original/D5_07_RangeChecksum.sol";
import {RangeChecksum as OBF_RangeChecksum} from "../contracts/D5/obfuscated/D5_07_RangeChecksum.sol";

contract D5_Oracle is Test {

    function test_D5_01_ArraySum() public {
        ORIG_ArraySum o = new ORIG_ArraySum();
        OBF_ArraySum b = new OBF_ArraySum();
        uint256[] memory xs = new uint256[](5);
        xs[0]=1; xs[1]=2; xs[2]=3; xs[3]=4; xs[4]=5;
        assertEq(o.total(xs), b.total(xs), "obfuscated output diverges from original");
    }

    function test_D5_02_WeightedMean() public {
        ORIG_WeightedMean o = new ORIG_WeightedMean();
        OBF_WeightedMean b = new OBF_WeightedMean();
        uint256[] memory xs = new uint256[](5);
        xs[0]=1; xs[1]=2; xs[2]=3; xs[3]=4; xs[4]=5;
        assertEq(o.mean(xs, xs), b.mean(xs, xs), "obfuscated output diverges from original");
    }

    function test_D5_03_MaxFinder() public {
        ORIG_MaxFinder o = new ORIG_MaxFinder();
        OBF_MaxFinder b = new OBF_MaxFinder();
        uint256[] memory xs = new uint256[](5);
        xs[0]=1; xs[1]=2; xs[2]=3; xs[3]=4; xs[4]=5;
        assertEq(o.largest(xs), b.largest(xs), "obfuscated output diverges from original");
    }

    function test_D5_05_CountAbove() public {
        ORIG_CountAbove o = new ORIG_CountAbove();
        OBF_CountAbove b = new OBF_CountAbove();
        uint256[] memory xs = new uint256[](5);
        xs[0]=1; xs[1]=2; xs[2]=3; xs[3]=4; xs[4]=5;
        assertEq(o.howMany(xs, 2), b.howMany(xs, 2), "obfuscated output diverges from original");
    }

    function test_D5_06_RunningProduct() public {
        ORIG_RunningProduct o = new ORIG_RunningProduct();
        OBF_RunningProduct b = new OBF_RunningProduct();
        uint256[] memory xs = new uint256[](5);
        xs[0]=1; xs[1]=2; xs[2]=3; xs[3]=4; xs[4]=5;
        assertEq(o.product(xs), b.product(xs), "obfuscated output diverges from original");
    }

    function test_D5_07_RangeChecksum() public {
        ORIG_RangeChecksum o = new ORIG_RangeChecksum();
        OBF_RangeChecksum b = new OBF_RangeChecksum();
        assertEq(o.checksum(1, 20), b.checksum(1, 20), "obfuscated output diverges from original");
    }
}
