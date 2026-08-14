// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract ArbitrationFund {
    mapping(address => uint256) public award;
    mapping(address => uint256) public costs;
    uint256 result;

    function setA(address to, uint256 v) external { award[to] = v; }
    function setB(address to, uint256 v) external { costs[to] = v; }

    function payAward() external {
        result += award[msg.sender];
        award[msg.sender] = 0;
        payable(msg.sender).transfer(result);
    }

    function payCosts() external {
        result += costs[msg.sender];
        costs[msg.sender] = 0;
        payable(msg.sender).transfer(result);
    }

    receive() external payable {}
}
