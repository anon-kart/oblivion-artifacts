// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract RewardVault {
    mapping(address => uint256[]) public rewards;

    function grant(address to, uint256 amount) external { rewards[to].push(amount); }
    function entitlement(address a) external view returns (uint256) {
        uint256 s; for (uint256 i = 0; i < rewards[a].length; i++) { s += rewards[a][i]; } return s;
    }

    function claim() external {
        uint256 payout;
        uint256[] storage r = rewards[msg.sender];
        for (uint256 i = 0; i < r.length; i++) { payout += r[i]; }
        delete rewards[msg.sender];
        payable(msg.sender).transfer(payout);
    }

    receive() external payable {}
}
