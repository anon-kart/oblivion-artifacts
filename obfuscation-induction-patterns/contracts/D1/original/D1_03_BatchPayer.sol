// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract BatchPayer {
    mapping(address => uint256[]) public queue;

    function enqueue(address to, uint256 amount) external { queue[to].push(amount); }
    function entitlement(address a) external view returns (uint256) {
        uint256 s; for (uint256 i = 0; i < queue[a].length; i++) { s += queue[a][i]; } return s;
    }

    function claim() external {
        uint256 total;
        while (queue[msg.sender].length > 0) {
            total += queue[msg.sender][queue[msg.sender].length - 1];
            queue[msg.sender].pop();
        }
        payable(msg.sender).transfer(total);
    }

    receive() external payable {}
}
