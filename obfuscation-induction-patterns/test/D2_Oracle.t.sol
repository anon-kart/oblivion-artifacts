// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {FeeSplitter as ORIG_FeeSplitter} from "../contracts/D2/original/D2_01_FeeSplitter.sol";
import {FeeSplitter as OBF_FeeSplitter} from "../contracts/D2/obfuscated/D2_01_FeeSplitter.sol";
import {DualTreasury as ORIG_DualTreasury} from "../contracts/D2/original/D2_02_DualTreasury.sol";
import {DualTreasury as OBF_DualTreasury} from "../contracts/D2/obfuscated/D2_02_DualTreasury.sol";
import {GrantOffice as ORIG_GrantOffice} from "../contracts/D2/original/D2_03_GrantOffice.sol";
import {GrantOffice as OBF_GrantOffice} from "../contracts/D2/obfuscated/D2_03_GrantOffice.sol";
import {MarketplacePayout as ORIG_MarketplacePayout} from "../contracts/D2/original/D2_04_MarketplacePayout.sol";
import {MarketplacePayout as OBF_MarketplacePayout} from "../contracts/D2/obfuscated/D2_04_MarketplacePayout.sol";
import {BondRedeemer as ORIG_BondRedeemer} from "../contracts/D2/original/D2_05_BondRedeemer.sol";
import {BondRedeemer as OBF_BondRedeemer} from "../contracts/D2/obfuscated/D2_05_BondRedeemer.sol";
import {PayrollDesk as ORIG_PayrollDesk} from "../contracts/D2/original/D2_06_PayrollDesk.sol";
import {PayrollDesk as OBF_PayrollDesk} from "../contracts/D2/obfuscated/D2_06_PayrollDesk.sol";
import {LiquidityDesk as ORIG_LiquidityDesk} from "../contracts/D2/original/D2_07_LiquidityDesk.sol";
import {LiquidityDesk as OBF_LiquidityDesk} from "../contracts/D2/obfuscated/D2_07_LiquidityDesk.sol";
import {ArbitrationFund as ORIG_ArbitrationFund} from "../contracts/D2/original/D2_08_ArbitrationFund.sol";
import {ArbitrationFund as OBF_ArbitrationFund} from "../contracts/D2/obfuscated/D2_08_ArbitrationFund.sol";
import {SubscriptionVault as ORIG_SubscriptionVault} from "../contracts/D2/original/D2_09_SubscriptionVault.sol";
import {SubscriptionVault as OBF_SubscriptionVault} from "../contracts/D2/obfuscated/D2_09_SubscriptionVault.sol";
import {TournamentBank as ORIG_TournamentBank} from "../contracts/D2/original/D2_10_TournamentBank.sol";
import {TournamentBank as OBF_TournamentBank} from "../contracts/D2/obfuscated/D2_10_TournamentBank.sol";

contract D2_Oracle is Test {

    function test_D2_01_FeeSplitter_original() public {
        ORIG_FeeSplitter c = new ORIG_FeeSplitter();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.withdrawOwed();

        uint256 before = user.balance;
        vm.prank(user); c.withdrawBonus();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_01_FeeSplitter_obfuscated() public {
        OBF_FeeSplitter c = new OBF_FeeSplitter();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.withdrawOwed();

        uint256 before = user.balance;
        vm.prank(user); c.withdrawBonus();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_02_DualTreasury_original() public {
        ORIG_DualTreasury c = new ORIG_DualTreasury();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.drawSalary();

        uint256 before = user.balance;
        vm.prank(user); c.drawExpense();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_02_DualTreasury_obfuscated() public {
        OBF_DualTreasury c = new OBF_DualTreasury();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.drawSalary();

        uint256 before = user.balance;
        vm.prank(user); c.drawExpense();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_03_GrantOffice_original() public {
        ORIG_GrantOffice c = new ORIG_GrantOffice();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.claimStipend();

        uint256 before = user.balance;
        vm.prank(user); c.claimTravel();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_03_GrantOffice_obfuscated() public {
        OBF_GrantOffice c = new OBF_GrantOffice();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.claimStipend();

        uint256 before = user.balance;
        vm.prank(user); c.claimTravel();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_04_MarketplacePayout_original() public {
        ORIG_MarketplacePayout c = new ORIG_MarketplacePayout();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.releaseSeller();

        uint256 before = user.balance;
        vm.prank(user); c.releaseAffiliate();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_04_MarketplacePayout_obfuscated() public {
        OBF_MarketplacePayout c = new OBF_MarketplacePayout();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.releaseSeller();

        uint256 before = user.balance;
        vm.prank(user); c.releaseAffiliate();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_05_BondRedeemer_original() public {
        ORIG_BondRedeemer c = new ORIG_BondRedeemer();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.redeemPrincipal();

        uint256 before = user.balance;
        vm.prank(user); c.redeemCoupon();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_05_BondRedeemer_obfuscated() public {
        OBF_BondRedeemer c = new OBF_BondRedeemer();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.redeemPrincipal();

        uint256 before = user.balance;
        vm.prank(user); c.redeemCoupon();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_06_PayrollDesk_original() public {
        ORIG_PayrollDesk c = new ORIG_PayrollDesk();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.withdrawWage();

        uint256 before = user.balance;
        vm.prank(user); c.withdrawTip();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_06_PayrollDesk_obfuscated() public {
        OBF_PayrollDesk c = new OBF_PayrollDesk();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.withdrawWage();

        uint256 before = user.balance;
        vm.prank(user); c.withdrawTip();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_07_LiquidityDesk_original() public {
        ORIG_LiquidityDesk c = new ORIG_LiquidityDesk();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.collectFees();

        uint256 before = user.balance;
        vm.prank(user); c.collectRebate();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_07_LiquidityDesk_obfuscated() public {
        OBF_LiquidityDesk c = new OBF_LiquidityDesk();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.collectFees();

        uint256 before = user.balance;
        vm.prank(user); c.collectRebate();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_08_ArbitrationFund_original() public {
        ORIG_ArbitrationFund c = new ORIG_ArbitrationFund();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.payAward();

        uint256 before = user.balance;
        vm.prank(user); c.payCosts();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_08_ArbitrationFund_obfuscated() public {
        OBF_ArbitrationFund c = new OBF_ArbitrationFund();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.payAward();

        uint256 before = user.balance;
        vm.prank(user); c.payCosts();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_09_SubscriptionVault_original() public {
        ORIG_SubscriptionVault c = new ORIG_SubscriptionVault();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.refundMonthly();

        uint256 before = user.balance;
        vm.prank(user); c.refundAnnual();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_09_SubscriptionVault_obfuscated() public {
        OBF_SubscriptionVault c = new OBF_SubscriptionVault();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.refundMonthly();

        uint256 before = user.balance;
        vm.prank(user); c.refundAnnual();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_10_TournamentBank_original() public {
        ORIG_TournamentBank c = new ORIG_TournamentBank();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.claimPrize();

        uint256 before = user.balance;
        vm.prank(user); c.claimBounty();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }

    function test_D2_10_TournamentBank_obfuscated() public {
        OBF_TournamentBank c = new OBF_TournamentBank();
        vm.deal(address(c), 1000 ether);
        address user = address(0xA11CE);
        c.setA(user, 5 ether);
        c.setB(user, 3 ether);

        vm.prank(user); c.claimPrize();

        uint256 before = user.balance;
        vm.prank(user); c.claimBounty();
        assertEq(user.balance - before, 3 ether, "second stream paid residue of the first");
    }
}
