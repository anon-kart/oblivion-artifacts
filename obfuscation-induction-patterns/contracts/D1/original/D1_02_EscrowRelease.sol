// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract EscrowRelease {
    mapping(address => uint256) public milestoneA;
    mapping(address => uint256) public milestoneB;

    function fund(address to, uint256 a, uint256 b) external { milestoneA[to] = a; milestoneB[to] = b; }
    function entitlement(address a) external view returns (uint256) { return milestoneA[a] + milestoneB[a]; }

    function claim() external {
        uint256 payout;
        if (milestoneA[msg.sender] > 0) { payout += milestoneA[msg.sender]; milestoneA[msg.sender] = 0; }
        if (milestoneB[msg.sender] > 0) { payout += milestoneB[msg.sender]; milestoneB[msg.sender] = 0; }
        payable(msg.sender).transfer(payout);
    }

    receive() external payable {}
}
