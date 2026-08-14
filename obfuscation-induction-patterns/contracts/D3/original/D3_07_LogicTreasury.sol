// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract LogicTreasury {
    address public owner;
    mapping(address => uint256) public balance;
    uint256 public reserve;

    function initialize() external {
        require(owner == address(0), "init");
        owner = msg.sender;
    }

    function credit(address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        balance[to] += amount;
    }


    function fundReserve(uint256 amount) external {
        require(msg.sender == owner, "not owner"); reserve += amount;
    }
    function readOwner() external view returns (address) { return owner; }

}
