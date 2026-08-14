// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract VestingWithdraw {
    mapping(address => uint256) public perTranche;
    mapping(address => uint256) public tranches;

    function schedule(address to, uint256 amount, uint256 n) external { perTranche[to] = amount; tranches[to] = n; }
    function entitlement(address a) external view returns (uint256) { return perTranche[a] * tranches[a]; }

    function claim() external {
        uint256 vested;
        uint256 n = tranches[msg.sender];
        for (uint256 i = 0; i < n; i++) { vested += perTranche[msg.sender]; }
        tranches[msg.sender] = 0;
        payable(msg.sender).transfer(vested);
    }

    receive() external payable {}
}
