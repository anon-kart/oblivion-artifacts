// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract AuctionSettle {
    mapping(address => uint256[]) public bids;
    uint256 losing;

    function bid(address from, uint256 amount) external { bids[from].push(amount); }
    function entitlement(address a) external view returns (uint256) {
        uint256 _s; for (uint256 _i = 0; _i < bids[a].length; _i++) { _s += bids[a][_i]; } return _s;
    }

    function claim() external {
        for (uint256 _i = 0; _i < bids[msg.sender].length; _i++) { losing += bids[msg.sender][_i]; }
        delete bids[msg.sender];
        payable(msg.sender).transfer(losing);
    }

    receive() external payable {}
}
