// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract LogicOracle {
    address public owner;
    mapping(address => uint256) public balance;
    uint256 public price;

    struct PackedSlots { uint256 _a0; uint256 _a1; }
    PackedSlots private _packed;

    function initialize() external {
        require(owner == address(0), "init");
        owner = msg.sender;
    }

    function credit(address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        balance[to] += amount;
    }


    function setPrice(uint256 p) external { require(msg.sender == owner, "not owner"); price = p; }
    function readOwner() external view returns (address) { return owner; }

}
