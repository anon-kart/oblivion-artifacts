// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract FeeCollector {
    mapping(address => uint256) public tradingFee;
    mapping(address => uint256) public listingFee;
    mapping(address => uint256) public storageFee;

    function assign(address to, uint256 t, uint256 l, uint256 s) external {
        tradingFee[to] = t; listingFee[to] = l; storageFee[to] = s;
    }
    function entitlement(address a) external view returns (uint256) {
        return tradingFee[a] + listingFee[a] + storageFee[a];
    }

    function claim() external {
        uint256 accrued;
        accrued += tradingFee[msg.sender];
        accrued += listingFee[msg.sender];
        accrued += storageFee[msg.sender];
        tradingFee[msg.sender] = 0; listingFee[msg.sender] = 0; storageFee[msg.sender] = 0;
        payable(msg.sender).transfer(accrued);
    }

    receive() external payable {}
}
