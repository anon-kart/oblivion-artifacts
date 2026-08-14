// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract SubscriptionVault {
    mapping(address => uint256) public monthly;
    mapping(address => uint256) public annual;
    uint256 refund;

    function setA(address to, uint256 v) external { monthly[to] = v; }
    function setB(address to, uint256 v) external { annual[to] = v; }

    function refundMonthly() external {
        refund += monthly[msg.sender];
        monthly[msg.sender] = 0;
        payable(msg.sender).transfer(refund);
    }

    function refundAnnual() external {
        refund += annual[msg.sender];
        annual[msg.sender] = 0;
        payable(msg.sender).transfer(refund);
    }

    receive() external payable {}
}
