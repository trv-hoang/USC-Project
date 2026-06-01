// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Sm01V1 {
    uint256 public total;

    function add(uint256 x) external {
        total = total + x;
    }
}
