// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract LiquidityDesk {
    mapping(address => uint256) public feeShare;
    mapping(address => uint256) public rebate;

    function setA(address to, uint256 v) external { feeShare[to] = v; }
    function setB(address to, uint256 v) external { rebate[to] = v; }

    function collectFees() external {
        uint256 owedNow;
        owedNow += feeShare[msg.sender];
        feeShare[msg.sender] = 0;
        payable(msg.sender).transfer(owedNow);
    }

    function collectRebate() external {
        uint256 owedNow;
        owedNow += rebate[msg.sender];
        rebate[msg.sender] = 0;
        payable(msg.sender).transfer(owedNow);
    }

    receive() external payable {}
}
