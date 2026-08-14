// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract RefundPool {
    mapping(address => uint256) public deposit;
    mapping(address => uint256) public penalty;
    uint256 refund;

    function record(address to, uint256 d, uint256 p) external { deposit[to] = d; penalty[to] = p; }
    function entitlement(address a) external view returns (uint256) { return deposit[a] - penalty[a]; }

    function claim() external {
        refund += deposit[msg.sender];
        refund -= penalty[msg.sender];
        deposit[msg.sender] = 0; penalty[msg.sender] = 0;
        payable(msg.sender).transfer(refund);
    }

    receive() external payable {}
}
