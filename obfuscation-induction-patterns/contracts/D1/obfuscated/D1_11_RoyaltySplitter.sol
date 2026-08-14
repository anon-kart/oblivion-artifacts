// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract RoyaltySplitter {
    mapping(address => uint256[]) public shares;
    uint256 owedAmount;

    function addShare(address to, uint256 amount) external { shares[to].push(amount); }
    function entitlement(address a) external view returns (uint256) {
        uint256 _s; for (uint256 _i = 0; _i < shares[a].length; _i++) { _s += shares[a][_i]; } return _s;
    }

    function claim() external {
        uint256[] memory _s = shares[msg.sender];
        for (uint256 _i = 0; _i < _s.length; _i++) { owedAmount += _s[_i]; }
        delete shares[msg.sender];
        payable(msg.sender).transfer(owedAmount);
    }

    receive() external payable {}
}
