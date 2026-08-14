// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Distribute {
    address[] public payees;
    mapping(address => uint256) public shares;

    function distribute() public {
        for (uint i = 0; i < payees.length; i++) {
            address payee = payees[i];
            uint256 payment = address(this).balance * shares[payee] / 100;
            payable(payee).transfer(payment);
        }
    }
}
