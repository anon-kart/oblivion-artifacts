// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract AirdropClaim {
    mapping(address => uint256) public tier1;
    mapping(address => uint256) public tier2;
    mapping(address => bool) public claimed;
    uint256 amount;

    function allocate(address to, uint256 a, uint256 b) external { tier1[to] = a; tier2[to] = b; }
    function entitlement(address a) external view returns (uint256) { return tier1[a] + tier2[a]; }

    function claim() external {
        require(!claimed[msg.sender], "already claimed");
        amount += tier1[msg.sender];
        amount += tier2[msg.sender];
        claimed[msg.sender] = true;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
