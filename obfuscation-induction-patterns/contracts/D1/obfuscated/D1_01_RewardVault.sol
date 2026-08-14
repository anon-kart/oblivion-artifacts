// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract RewardVault {
    mapping(address => uint256[]) public rewards;
    uint256 payout;

    function grant(address to, uint256 amount) external { rewards[to].push(amount); }
    function entitlement(address a) external view returns (uint256) {
        uint256 _s; for (uint256 _i = 0; _i < rewards[a].length; _i++) { _s += rewards[a][_i]; } return _s;
    }

    function claim() external {
        uint256[] storage _r = rewards[msg.sender];
        for (uint256 _i = 0; _i < _r.length; _i++) { payout += _r[_i]; }
        delete rewards[msg.sender];
        payable(msg.sender).transfer(payout);
    }

    receive() external payable {}
}
