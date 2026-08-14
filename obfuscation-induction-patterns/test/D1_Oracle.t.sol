// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {RewardVault as ORIG_RewardVault} from "../contracts/D1/original/D1_01_RewardVault.sol";
import {RewardVault as OBF_RewardVault} from "../contracts/D1/obfuscated/D1_01_RewardVault.sol";
import {EscrowRelease as ORIG_EscrowRelease} from "../contracts/D1/original/D1_02_EscrowRelease.sol";
import {EscrowRelease as OBF_EscrowRelease} from "../contracts/D1/obfuscated/D1_02_EscrowRelease.sol";
import {BatchPayer as ORIG_BatchPayer} from "../contracts/D1/original/D1_03_BatchPayer.sol";
import {BatchPayer as OBF_BatchPayer} from "../contracts/D1/obfuscated/D1_03_BatchPayer.sol";
import {FeeCollector as ORIG_FeeCollector} from "../contracts/D1/original/D1_04_FeeCollector.sol";
import {FeeCollector as OBF_FeeCollector} from "../contracts/D1/obfuscated/D1_04_FeeCollector.sol";
import {RefundPool as ORIG_RefundPool} from "../contracts/D1/original/D1_05_RefundPool.sol";
import {RefundPool as OBF_RefundPool} from "../contracts/D1/obfuscated/D1_05_RefundPool.sol";
import {StakingRewards as ORIG_StakingRewards} from "../contracts/D1/original/D1_06_StakingRewards.sol";
import {StakingRewards as OBF_StakingRewards} from "../contracts/D1/obfuscated/D1_06_StakingRewards.sol";
import {AirdropClaim as ORIG_AirdropClaim} from "../contracts/D1/original/D1_07_AirdropClaim.sol";
import {AirdropClaim as OBF_AirdropClaim} from "../contracts/D1/obfuscated/D1_07_AirdropClaim.sol";
import {AuctionSettle as ORIG_AuctionSettle} from "../contracts/D1/original/D1_08_AuctionSettle.sol";
import {AuctionSettle as OBF_AuctionSettle} from "../contracts/D1/obfuscated/D1_08_AuctionSettle.sol";
import {VestingWithdraw as ORIG_VestingWithdraw} from "../contracts/D1/original/D1_09_VestingWithdraw.sol";
import {VestingWithdraw as OBF_VestingWithdraw} from "../contracts/D1/obfuscated/D1_09_VestingWithdraw.sol";
import {InsuranceClaim as ORIG_InsuranceClaim} from "../contracts/D1/original/D1_10_InsuranceClaim.sol";
import {InsuranceClaim as OBF_InsuranceClaim} from "../contracts/D1/obfuscated/D1_10_InsuranceClaim.sol";
import {RoyaltySplitter as ORIG_RoyaltySplitter} from "../contracts/D1/original/D1_11_RoyaltySplitter.sol";
import {RoyaltySplitter as OBF_RoyaltySplitter} from "../contracts/D1/obfuscated/D1_11_RoyaltySplitter.sol";
import {LoyaltyRedeem as ORIG_LoyaltyRedeem} from "../contracts/D1/original/D1_12_LoyaltyRedeem.sol";
import {LoyaltyRedeem as OBF_LoyaltyRedeem} from "../contracts/D1/obfuscated/D1_12_LoyaltyRedeem.sol";
import {DividendPayout as ORIG_DividendPayout} from "../contracts/D1/original/D1_13_DividendPayout.sol";
import {DividendPayout as OBF_DividendPayout} from "../contracts/D1/obfuscated/D1_13_DividendPayout.sol";

contract D1_Oracle is Test {

    function test_D1_01_RewardVault_original() public {
        ORIG_RewardVault c = new ORIG_RewardVault();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.grant(alice, 10 ether); c.grant(bob, 1 ether);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_01_RewardVault_obfuscated() public {
        OBF_RewardVault c = new OBF_RewardVault();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.grant(alice, 10 ether); c.grant(bob, 1 ether);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_02_EscrowRelease_original() public {
        ORIG_EscrowRelease c = new ORIG_EscrowRelease();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.fund(alice, 6 ether, 4 ether); c.fund(bob, 1 ether, 0);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_02_EscrowRelease_obfuscated() public {
        OBF_EscrowRelease c = new OBF_EscrowRelease();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.fund(alice, 6 ether, 4 ether); c.fund(bob, 1 ether, 0);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_03_BatchPayer_original() public {
        ORIG_BatchPayer c = new ORIG_BatchPayer();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.enqueue(alice, 10 ether); c.enqueue(bob, 1 ether);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_03_BatchPayer_obfuscated() public {
        OBF_BatchPayer c = new OBF_BatchPayer();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.enqueue(alice, 10 ether); c.enqueue(bob, 1 ether);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_04_FeeCollector_original() public {
        ORIG_FeeCollector c = new ORIG_FeeCollector();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.assign(alice, 5 ether, 3 ether, 2 ether); c.assign(bob, 1 ether, 0, 0);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_04_FeeCollector_obfuscated() public {
        OBF_FeeCollector c = new OBF_FeeCollector();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.assign(alice, 5 ether, 3 ether, 2 ether); c.assign(bob, 1 ether, 0, 0);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_05_RefundPool_original() public {
        ORIG_RefundPool c = new ORIG_RefundPool();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.record(alice, 12 ether, 2 ether); c.record(bob, 1 ether, 0);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_05_RefundPool_obfuscated() public {
        OBF_RefundPool c = new OBF_RefundPool();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.record(alice, 12 ether, 2 ether); c.record(bob, 1 ether, 0);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_06_StakingRewards_original() public {
        ORIG_StakingRewards c = new ORIG_StakingRewards();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.stake(alice, 5 ether, 2); c.stake(bob, 1 ether, 1);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_06_StakingRewards_obfuscated() public {
        OBF_StakingRewards c = new OBF_StakingRewards();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.stake(alice, 5 ether, 2); c.stake(bob, 1 ether, 1);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_07_AirdropClaim_original() public {
        ORIG_AirdropClaim c = new ORIG_AirdropClaim();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.allocate(alice, 7 ether, 3 ether); c.allocate(bob, 1 ether, 0);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_07_AirdropClaim_obfuscated() public {
        OBF_AirdropClaim c = new OBF_AirdropClaim();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.allocate(alice, 7 ether, 3 ether); c.allocate(bob, 1 ether, 0);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_08_AuctionSettle_original() public {
        ORIG_AuctionSettle c = new ORIG_AuctionSettle();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.bid(alice, 10 ether); c.bid(bob, 1 ether);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_08_AuctionSettle_obfuscated() public {
        OBF_AuctionSettle c = new OBF_AuctionSettle();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.bid(alice, 10 ether); c.bid(bob, 1 ether);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_09_VestingWithdraw_original() public {
        ORIG_VestingWithdraw c = new ORIG_VestingWithdraw();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.schedule(alice, 5 ether, 2); c.schedule(bob, 1 ether, 1);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_09_VestingWithdraw_obfuscated() public {
        OBF_VestingWithdraw c = new OBF_VestingWithdraw();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.schedule(alice, 5 ether, 2); c.schedule(bob, 1 ether, 1);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_10_InsuranceClaim_original() public {
        ORIG_InsuranceClaim c = new ORIG_InsuranceClaim();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.file(alice, 4 ether, 3 ether, 3 ether); c.file(bob, 1 ether, 0, 0);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_10_InsuranceClaim_obfuscated() public {
        OBF_InsuranceClaim c = new OBF_InsuranceClaim();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.file(alice, 4 ether, 3 ether, 3 ether); c.file(bob, 1 ether, 0, 0);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_11_RoyaltySplitter_original() public {
        ORIG_RoyaltySplitter c = new ORIG_RoyaltySplitter();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.addShare(alice, 10 ether); c.addShare(bob, 1 ether);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_11_RoyaltySplitter_obfuscated() public {
        OBF_RoyaltySplitter c = new OBF_RoyaltySplitter();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.addShare(alice, 10 ether); c.addShare(bob, 1 ether);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_12_LoyaltyRedeem_original() public {
        ORIG_LoyaltyRedeem c = new ORIG_LoyaltyRedeem();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.award(alice, 10 ether); c.award(bob, 1 ether);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_12_LoyaltyRedeem_obfuscated() public {
        OBF_LoyaltyRedeem c = new OBF_LoyaltyRedeem();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.award(alice, 10 ether); c.award(bob, 1 ether);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_13_DividendPayout_original() public {
        ORIG_DividendPayout c = new ORIG_DividendPayout();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.register(alice, 5 ether, 2); c.register(bob, 1 ether, 1);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }

    function test_D1_13_DividendPayout_obfuscated() public {
        OBF_DividendPayout c = new OBF_DividendPayout();
        vm.deal(address(c), 1000 ether);
        address alice = address(0xA11CE);
        address bob   = address(0xB0B);
        c.register(alice, 5 ether, 2); c.register(bob, 1 ether, 1);

        uint256 bobDue = c.entitlement(bob);

        vm.prank(alice); c.claim();

        uint256 before = bob.balance;
        vm.prank(bob); c.claim();
        assertEq(bob.balance - before, bobDue, "bob overpaid: accumulator carried over");
    }
}
