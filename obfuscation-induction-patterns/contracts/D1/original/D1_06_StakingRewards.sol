// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract StakingRewards {
    mapping(address => uint256) public staked;
    mapping(address => uint256) public epochs;
    uint256 public constant RATE = 1;

    function stake(address to, uint256 amount, uint256 e) external { staked[to] = amount; epochs[to] = e; }
    function entitlement(address a) external view returns (uint256) { return staked[a] * epochs[a] * RATE; }

    function claim() external {
        uint256 earned;
        for (uint256 i = 0; i < epochs[msg.sender]; i++) { earned += staked[msg.sender] * RATE; }
        epochs[msg.sender] = 0;
        payable(msg.sender).transfer(earned);
    }

    receive() external payable {}
}
