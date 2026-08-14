// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract BondRedeemer {
    mapping(address => uint256) public principal;
    mapping(address => uint256) public coupon;

    function setA(address to, uint256 v) external { principal[to] = v; }
    function setB(address to, uint256 v) external { coupon[to] = v; }

    function redeemPrincipal() external {
        uint256 value;
        value += principal[msg.sender];
        principal[msg.sender] = 0;
        payable(msg.sender).transfer(value);
    }

    function redeemCoupon() external {
        uint256 value;
        value += coupon[msg.sender];
        coupon[msg.sender] = 0;
        payable(msg.sender).transfer(value);
    }

    receive() external payable {}
}
