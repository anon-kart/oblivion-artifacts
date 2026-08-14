// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract GrantOffice {
    mapping(address => uint256) public stipend;
    mapping(address => uint256) public travel;
    uint256 sum;

    function setA(address to, uint256 v) external { stipend[to] = v; }
    function setB(address to, uint256 v) external { travel[to] = v; }

    function claimStipend() external {
        sum += stipend[msg.sender];
        stipend[msg.sender] = 0;
        payable(msg.sender).transfer(sum);
    }

    function claimTravel() external {
        sum += travel[msg.sender];
        travel[msg.sender] = 0;
        payable(msg.sender).transfer(sum);
    }

    receive() external payable {}
}
