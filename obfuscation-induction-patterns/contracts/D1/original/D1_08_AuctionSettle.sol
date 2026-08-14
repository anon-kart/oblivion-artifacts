// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract AuctionSettle {
    mapping(address => uint256[]) public bids;

    function bid(address from, uint256 amount) external { bids[from].push(amount); }
    function entitlement(address a) external view returns (uint256) {
        uint256 s; for (uint256 i = 0; i < bids[a].length; i++) { s += bids[a][i]; } return s;
    }

    function claim() external {
        uint256 losing;
        for (uint256 i = 0; i < bids[msg.sender].length; i++) { losing += bids[msg.sender][i]; }
        delete bids[msg.sender];
        payable(msg.sender).transfer(losing);
    }

    receive() external payable {}
}
