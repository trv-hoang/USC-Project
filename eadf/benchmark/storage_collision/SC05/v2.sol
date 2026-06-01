// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Sc05V2 {
    uint256 public value; // slot 0 (unchanged)
    address public owner; // slot 1 (unchanged)

    function setValue(uint256 v) external {
        value = v;
    }
}
