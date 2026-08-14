// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract PayrollDesk {
    mapping(address => uint256) public wage;
    mapping(address => uint256) public tip;
    uint256 acc;

    function setA(address to, uint256 v) external { wage[to] = v; }
    function setB(address to, uint256 v) external { tip[to] = v; }

    function withdrawWage() external {
        acc += wage[msg.sender];
        wage[msg.sender] = 0;
        payable(msg.sender).transfer(acc);
    }

    function withdrawTip() external {
        acc += tip[msg.sender];
        tip[msg.sender] = 0;
        payable(msg.sender).transfer(acc);
    }

    receive() external payable {}
}
