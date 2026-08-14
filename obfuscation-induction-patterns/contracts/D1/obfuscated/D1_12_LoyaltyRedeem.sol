// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract LoyaltyRedeem {
    mapping(address => uint256) public points;
    uint256 public constant WEI_PER_POINT = 1;
    uint256 value;

    function award(address to, uint256 p) external { points[to] = p; }
    function entitlement(address a) external view returns (uint256) { return points[a] * WEI_PER_POINT; }

    function claim() external {
        if (points[msg.sender] > 0) {
            value += points[msg.sender] * WEI_PER_POINT;
            points[msg.sender] = 0;
        }
        payable(msg.sender).transfer(value);
    }

    receive() external payable {}
}
