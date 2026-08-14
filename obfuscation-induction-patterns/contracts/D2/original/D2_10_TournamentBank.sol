// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract TournamentBank {
    mapping(address => uint256) public prize;
    mapping(address => uint256) public bounty;

    function setA(address to, uint256 v) external { prize[to] = v; }
    function setB(address to, uint256 v) external { bounty[to] = v; }

    function claimPrize() external {
        uint256 credit;
        credit += prize[msg.sender];
        prize[msg.sender] = 0;
        payable(msg.sender).transfer(credit);
    }

    function claimBounty() external {
        uint256 credit;
        credit += bounty[msg.sender];
        bounty[msg.sender] = 0;
        payable(msg.sender).transfer(credit);
    }

    receive() external payable {}
}
