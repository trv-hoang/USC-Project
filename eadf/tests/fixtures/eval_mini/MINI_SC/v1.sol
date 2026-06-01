// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MiniScV1 {
    uint256 public value; // slot 0
    function setValue(uint256 v) external { value = v; }
}
