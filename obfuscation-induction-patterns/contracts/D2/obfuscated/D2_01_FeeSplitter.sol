// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract FeeSplitter {
    mapping(address => uint256) public owed;
    mapping(address => uint256) public bonus;
    uint256 total;

    function setA(address to, uint256 v) external { owed[to] = v; }
    function setB(address to, uint256 v) external { bonus[to] = v; }

    function withdrawOwed() external {
        total += owed[msg.sender];
        owed[msg.sender] = 0;
        payable(msg.sender).transfer(total);
    }

    function withdrawBonus() external {
        total += bonus[msg.sender];
        bonus[msg.sender] = 0;
        payable(msg.sender).transfer(total);
    }

    receive() external payable {}
}
