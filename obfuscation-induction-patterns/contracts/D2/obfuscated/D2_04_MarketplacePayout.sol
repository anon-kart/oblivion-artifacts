// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract MarketplacePayout {
    mapping(address => uint256) public seller;
    mapping(address => uint256) public affiliate;
    uint256 payout;

    function setA(address to, uint256 v) external { seller[to] = v; }
    function setB(address to, uint256 v) external { affiliate[to] = v; }

    function releaseSeller() external {
        payout += seller[msg.sender];
        seller[msg.sender] = 0;
        payable(msg.sender).transfer(payout);
    }

    function releaseAffiliate() external {
        payout += affiliate[msg.sender];
        affiliate[msg.sender] = 0;
        payable(msg.sender).transfer(payout);
    }

    receive() external payable {}
}
