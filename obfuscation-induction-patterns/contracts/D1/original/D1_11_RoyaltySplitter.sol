// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract RoyaltySplitter {
    mapping(address => uint256[]) public shares;

    function addShare(address to, uint256 amount) external { shares[to].push(amount); }
    function entitlement(address a) external view returns (uint256) {
        uint256 s; for (uint256 i = 0; i < shares[a].length; i++) { s += shares[a][i]; } return s;
    }

    function claim() external {
        uint256 owedAmount;
        uint256[] memory s = shares[msg.sender];
        for (uint256 i = 0; i < s.length; i++) { owedAmount += s[i]; }
        delete shares[msg.sender];
        payable(msg.sender).transfer(owedAmount);
    }

    receive() external payable {}
}
