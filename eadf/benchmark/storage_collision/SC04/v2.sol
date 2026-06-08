// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Sc04V2 {
    uint256 public value; // slot 0 (unchanged)
    address public owner; // slot 1 (unchanged)
    uint256 public extra; // slot 2 (appended)

    function setValue(uint256 v) external {
        value = v;
    }

    function setExtra(uint256 e) external {
        extra = e;
    }
}
