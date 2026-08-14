// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract DualTreasury {
    mapping(address => uint256) public salary;
    mapping(address => uint256) public expense;

    function setA(address to, uint256 v) external { salary[to] = v; }
    function setB(address to, uint256 v) external { expense[to] = v; }

    function drawSalary() external {
        uint256 amount;
        amount += salary[msg.sender];
        salary[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    function drawExpense() external {
        uint256 amount;
        amount += expense[msg.sender];
        expense[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
