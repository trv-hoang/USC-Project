// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Sm01V2 {
    uint256 public total;

    function add(uint256 amount) external {
        total += amount;
    }
}
