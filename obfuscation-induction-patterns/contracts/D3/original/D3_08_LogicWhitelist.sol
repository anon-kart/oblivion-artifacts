// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract LogicWhitelist {
    address public owner;
    mapping(address => uint256) public balance;
    mapping(address => bool) public allowed;

    function initialize() external {
        require(owner == address(0), "init");
        owner = msg.sender;
    }

    function credit(address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        balance[to] += amount;
    }


    function allow(address a) external { require(msg.sender == owner, "not owner"); allowed[a] = true; }
    function readOwner() external view returns (address) { return owner; }

}
