// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract LogicVault {
    address public owner;
    mapping(address => uint256) public balance;

    function initialize() external {
        require(owner == address(0), "init");
        owner = msg.sender;
    }

    function credit(address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        balance[to] += amount;
    }


    function withdraw(uint256 amount) external {
        require(balance[msg.sender] >= amount, "funds");
        balance[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}

}
