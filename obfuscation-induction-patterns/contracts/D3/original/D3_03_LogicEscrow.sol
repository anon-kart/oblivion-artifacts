// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract LogicEscrow {
    address public owner;
    mapping(address => uint256) public balance;
    uint256 public locked;

    function initialize() external {
        require(owner == address(0), "init");
        owner = msg.sender;
    }

    function credit(address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        balance[to] += amount;
    }


    function lock(uint256 amount) external {
        require(balance[msg.sender] >= amount, "funds");
        balance[msg.sender] -= amount; locked += amount;
    }
    function readOwner() external view returns (address) { return owner; }

}
