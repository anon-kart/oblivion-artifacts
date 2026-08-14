// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract BatchPayer {
    mapping(address => uint256[]) public queue;
    uint256 total;

    function enqueue(address to, uint256 amount) external { queue[to].push(amount); }
    function entitlement(address a) external view returns (uint256) {
        uint256 _s; for (uint256 _i = 0; _i < queue[a].length; _i++) { _s += queue[a][_i]; } return _s;
    }

    function claim() external {
        while (queue[msg.sender].length > 0) {
            total += queue[msg.sender][queue[msg.sender].length - 1];
            queue[msg.sender].pop();
        }
        payable(msg.sender).transfer(total);
    }

    receive() external payable {}
}
