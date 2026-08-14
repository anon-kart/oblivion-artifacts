// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract DividendPayout {
    mapping(address => uint256) public holding;
    mapping(address => uint256) public periods;
    uint256 public constant DIVIDEND = 1;
    uint256 dividend;

    function register(address to, uint256 h, uint256 p) external { holding[to] = h; periods[to] = p; }
    function entitlement(address a) external view returns (uint256) { return holding[a] * periods[a] * DIVIDEND; }

    function claim() external {
        uint256 _p = periods[msg.sender];
        while (_p > 0) { dividend += holding[msg.sender] * DIVIDEND; _p--; }
        periods[msg.sender] = 0;
        payable(msg.sender).transfer(dividend);
    }

    receive() external payable {}
}
