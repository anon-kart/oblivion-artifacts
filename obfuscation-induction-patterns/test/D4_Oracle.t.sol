// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {FeeMath as ORIG_FeeMath} from "../contracts/D4/original/D4_01_FeeMath.sol";
import {FeeMath as OBF_FeeMath} from "../contracts/D4/obfuscated/D4_01_FeeMath.sol";
import {InterestAccrual as ORIG_InterestAccrual} from "../contracts/D4/original/D4_02_InterestAccrual.sol";
import {InterestAccrual as OBF_InterestAccrual} from "../contracts/D4/obfuscated/D4_02_InterestAccrual.sol";
import {TierPricing as ORIG_TierPricing} from "../contracts/D4/original/D4_03_TierPricing.sol";
import {TierPricing as OBF_TierPricing} from "../contracts/D4/obfuscated/D4_03_TierPricing.sol";
import {DecimalScaler as ORIG_DecimalScaler} from "../contracts/D4/original/D4_04_DecimalScaler.sol";
import {DecimalScaler as OBF_DecimalScaler} from "../contracts/D4/obfuscated/D4_04_DecimalScaler.sol";
import {RewardCurve as ORIG_RewardCurve} from "../contracts/D4/original/D4_05_RewardCurve.sol";
import {RewardCurve as OBF_RewardCurve} from "../contracts/D4/obfuscated/D4_05_RewardCurve.sol";
import {SlippageGuard as ORIG_SlippageGuard} from "../contracts/D4/original/D4_06_SlippageGuard.sol";
import {SlippageGuard as OBF_SlippageGuard} from "../contracts/D4/obfuscated/D4_06_SlippageGuard.sol";
import {GasEstimator as ORIG_GasEstimator} from "../contracts/D4/original/D4_07_GasEstimator.sol";
import {GasEstimator as OBF_GasEstimator} from "../contracts/D4/obfuscated/D4_07_GasEstimator.sol";
import {LotteryOdds as ORIG_LotteryOdds} from "../contracts/D4/original/D4_08_LotteryOdds.sol";
import {LotteryOdds as OBF_LotteryOdds} from "../contracts/D4/obfuscated/D4_08_LotteryOdds.sol";
import {CollateralRatio as ORIG_CollateralRatio} from "../contracts/D4/original/D4_09_CollateralRatio.sol";
import {CollateralRatio as OBF_CollateralRatio} from "../contracts/D4/obfuscated/D4_09_CollateralRatio.sol";
import {TaxWithholding as ORIG_TaxWithholding} from "../contracts/D4/original/D4_10_TaxWithholding.sol";
import {TaxWithholding as OBF_TaxWithholding} from "../contracts/D4/obfuscated/D4_10_TaxWithholding.sol";

contract D4_Oracle is Test {

    function test_D4_01_FeeMath() public {
        ORIG_FeeMath o = new ORIG_FeeMath();
        OBF_FeeMath b = new OBF_FeeMath();
        assertEq(o.quote(1_000_000), b.quote(1_000_000), "obfuscated output diverges from original");
    }

    function test_D4_02_InterestAccrual() public {
        ORIG_InterestAccrual o = new ORIG_InterestAccrual();
        OBF_InterestAccrual b = new OBF_InterestAccrual();
        assertEq(o.accrue(1_000_000, 86400), b.accrue(1_000_000, 86400), "obfuscated output diverges from original");
    }

    function test_D4_03_TierPricing() public {
        ORIG_TierPricing o = new ORIG_TierPricing();
        OBF_TierPricing b = new OBF_TierPricing();
        assertEq(o.priceFor(250), b.priceFor(250), "obfuscated output diverges from original");
    }

    function test_D4_04_DecimalScaler() public {
        ORIG_DecimalScaler o = new ORIG_DecimalScaler();
        OBF_DecimalScaler b = new OBF_DecimalScaler();
        assertEq(o.scale(1234, 6, 18), b.scale(1234, 6, 18), "obfuscated output diverges from original");
    }

    function test_D4_05_RewardCurve() public {
        ORIG_RewardCurve o = new ORIG_RewardCurve();
        OBF_RewardCurve b = new OBF_RewardCurve();
        assertEq(o.reward(3000), b.reward(3000), "obfuscated output diverges from original");
    }

    function test_D4_06_SlippageGuard() public {
        ORIG_SlippageGuard o = new ORIG_SlippageGuard();
        OBF_SlippageGuard b = new OBF_SlippageGuard();
        assertEq(o.minOut(1_000_000, 50), b.minOut(1_000_000, 50), "obfuscated output diverges from original");
    }

    function test_D4_07_GasEstimator() public {
        ORIG_GasEstimator o = new ORIG_GasEstimator();
        OBF_GasEstimator b = new OBF_GasEstimator();
        assertEq(o.estimate(17), b.estimate(17), "obfuscated output diverges from original");
    }

    function test_D4_08_LotteryOdds() public {
        ORIG_LotteryOdds o = new ORIG_LotteryOdds();
        OBF_LotteryOdds b = new OBF_LotteryOdds();
        assertEq(o.share(37, 1_000_000), b.share(37, 1_000_000), "obfuscated output diverges from original");
    }

    function test_D4_09_CollateralRatio() public {
        ORIG_CollateralRatio o = new ORIG_CollateralRatio();
        OBF_CollateralRatio b = new OBF_CollateralRatio();
        assertEq(o.healthy(300, 150), b.healthy(300, 150), "obfuscated output diverges from original");
    }

    function test_D4_10_TaxWithholding() public {
        ORIG_TaxWithholding o = new ORIG_TaxWithholding();
        OBF_TaxWithholding b = new OBF_TaxWithholding();
        assertEq(o.withhold(5000), b.withhold(5000), "obfuscated output diverges from original");
    }
}
