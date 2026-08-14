// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract InsuranceClaim {
    mapping(address => uint256) public base;
    mapping(address => uint256) public excess;
    mapping(address => uint256) public adjust;

    function file(address to, uint256 b, uint256 e, uint256 j) external { base[to] = b; excess[to] = e; adjust[to] = j; }
    function entitlement(address a) external view returns (uint256) { return base[a] + excess[a] + adjust[a]; }

    function claim() external {
        uint256 settlement;
        settlement += base[msg.sender];
        settlement += excess[msg.sender];
        settlement += adjust[msg.sender];
        base[msg.sender] = 0; excess[msg.sender] = 0; adjust[msg.sender] = 0;
        payable(msg.sender).transfer(settlement);
    }

    receive() external payable {}
}
