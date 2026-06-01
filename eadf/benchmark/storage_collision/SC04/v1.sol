// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Sc04V1 {
    uint256 public value; // slot 0
    address public owner; // slot 1

    function setValue(uint256 v) external {
        value = v;
    }
}
