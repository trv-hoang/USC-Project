// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Sc05V1 {
    uint256 public value; // slot 0
    address public owner; // slot 1
    uint256 public deprecated; // slot 2 (unused, to be removed)

    function setValue(uint256 v) external {
        value = v;
    }
}
