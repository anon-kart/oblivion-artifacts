// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Test.sol";
import {LogicVault as ORIG_LogicVault} from "../contracts/D3/original/D3_01_LogicVault.sol";
import {LogicVault as OBF_LogicVault} from "../contracts/D3/obfuscated/D3_01_LogicVault.sol";
import {LogicRegistry as ORIG_LogicRegistry} from "../contracts/D3/original/D3_02_LogicRegistry.sol";
import {LogicRegistry as OBF_LogicRegistry} from "../contracts/D3/obfuscated/D3_02_LogicRegistry.sol";
import {LogicEscrow as ORIG_LogicEscrow} from "../contracts/D3/original/D3_03_LogicEscrow.sol";
import {LogicEscrow as OBF_LogicEscrow} from "../contracts/D3/obfuscated/D3_03_LogicEscrow.sol";
import {LogicStaking as ORIG_LogicStaking} from "../contracts/D3/original/D3_04_LogicStaking.sol";
import {LogicStaking as OBF_LogicStaking} from "../contracts/D3/obfuscated/D3_04_LogicStaking.sol";
import {LogicGovernor as ORIG_LogicGovernor} from "../contracts/D3/original/D3_05_LogicGovernor.sol";
import {LogicGovernor as OBF_LogicGovernor} from "../contracts/D3/obfuscated/D3_05_LogicGovernor.sol";
import {LogicOracle as ORIG_LogicOracle} from "../contracts/D3/original/D3_06_LogicOracle.sol";
import {LogicOracle as OBF_LogicOracle} from "../contracts/D3/obfuscated/D3_06_LogicOracle.sol";
import {LogicTreasury as ORIG_LogicTreasury} from "../contracts/D3/original/D3_07_LogicTreasury.sol";
import {LogicTreasury as OBF_LogicTreasury} from "../contracts/D3/obfuscated/D3_07_LogicTreasury.sol";
import {LogicWhitelist as ORIG_LogicWhitelist} from "../contracts/D3/original/D3_08_LogicWhitelist.sol";
import {LogicWhitelist as OBF_LogicWhitelist} from "../contracts/D3/obfuscated/D3_08_LogicWhitelist.sol";
import {LogicBridge as ORIG_LogicBridge} from "../contracts/D3/original/D3_09_LogicBridge.sol";
import {LogicBridge as OBF_LogicBridge} from "../contracts/D3/obfuscated/D3_09_LogicBridge.sol";
import {LogicMarket as ORIG_LogicMarket} from "../contracts/D3/original/D3_10_LogicMarket.sol";
import {LogicMarket as OBF_LogicMarket} from "../contracts/D3/obfuscated/D3_10_LogicMarket.sol";

contract MiniProxy {
    address public owner;                       // slot 0, mirrors the logic layout
    mapping(address => uint256) public balance; // slot 1
    address private impl;

    constructor(address _impl) { impl = _impl; }

    fallback() external payable {
        address t = impl;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), t, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
    receive() external payable {}
}

contract D3_Oracle is Test {

    function test_D3_01_LogicVault_original() public {
        ORIG_LogicVault logic = new ORIG_LogicVault();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_01_LogicVault_obfuscated() public {
        OBF_LogicVault logic = new OBF_LogicVault();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_02_LogicRegistry_original() public {
        ORIG_LogicRegistry logic = new ORIG_LogicRegistry();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_02_LogicRegistry_obfuscated() public {
        OBF_LogicRegistry logic = new OBF_LogicRegistry();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_03_LogicEscrow_original() public {
        ORIG_LogicEscrow logic = new ORIG_LogicEscrow();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_03_LogicEscrow_obfuscated() public {
        OBF_LogicEscrow logic = new OBF_LogicEscrow();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_04_LogicStaking_original() public {
        ORIG_LogicStaking logic = new ORIG_LogicStaking();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_04_LogicStaking_obfuscated() public {
        OBF_LogicStaking logic = new OBF_LogicStaking();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_05_LogicGovernor_original() public {
        ORIG_LogicGovernor logic = new ORIG_LogicGovernor();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_05_LogicGovernor_obfuscated() public {
        OBF_LogicGovernor logic = new OBF_LogicGovernor();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_06_LogicOracle_original() public {
        ORIG_LogicOracle logic = new ORIG_LogicOracle();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_06_LogicOracle_obfuscated() public {
        OBF_LogicOracle logic = new OBF_LogicOracle();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_07_LogicTreasury_original() public {
        ORIG_LogicTreasury logic = new ORIG_LogicTreasury();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_07_LogicTreasury_obfuscated() public {
        OBF_LogicTreasury logic = new OBF_LogicTreasury();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_08_LogicWhitelist_original() public {
        ORIG_LogicWhitelist logic = new ORIG_LogicWhitelist();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_08_LogicWhitelist_obfuscated() public {
        OBF_LogicWhitelist logic = new OBF_LogicWhitelist();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_09_LogicBridge_original() public {
        ORIG_LogicBridge logic = new ORIG_LogicBridge();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_09_LogicBridge_obfuscated() public {
        OBF_LogicBridge logic = new OBF_LogicBridge();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_10_LogicMarket_original() public {
        ORIG_LogicMarket logic = new ORIG_LogicMarket();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }

    function test_D3_10_LogicMarket_obfuscated() public {
        OBF_LogicMarket logic = new OBF_LogicMarket();
        MiniProxy p = new MiniProxy(address(logic));
        address admin = address(0xA11CE);

        vm.prank(admin);
        (bool ok,) = address(p).call(abi.encodeWithSignature("initialize()"));
        assertTrue(ok, "initialize reverted through proxy");

        // slot 0 of the proxy must hold the admin: no layout displacement
        assertEq(p.owner(), admin, "owner slot displaced under delegatecall");

        // access control must still bind to that slot
        address mallory = address(0xBAD);
        vm.prank(mallory);
        (bool ok2,) = address(p).call(abi.encodeWithSignature("credit(address,uint256)", mallory, 1));
        assertFalse(ok2, "access control bypassed after layout change");
    }
}
