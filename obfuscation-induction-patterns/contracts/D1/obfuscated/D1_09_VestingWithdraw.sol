// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract VestingWithdraw {
    mapping(address => uint256) public perTranche;
    mapping(address => uint256) public tranches;
    uint256 vested;

    function schedule(address to, uint256 amount, uint256 n) external { perTranche[to] = amount; tranches[to] = n; }
    function entitlement(address a) external view returns (uint256) { return perTranche[a] * tranches[a]; }

    function claim() external {
        uint256 _n = tranches[msg.sender];
        for (uint256 _i = 0; _i < _n; _i++) { vested += perTranche[msg.sender]; }
        tranches[msg.sender] = 0;
        payable(msg.sender).transfer(vested);
    }

    receive() external payable {}
}
