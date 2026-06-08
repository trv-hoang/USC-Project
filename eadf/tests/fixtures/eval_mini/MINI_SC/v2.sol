// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MiniScV2 {
    uint256 public collisionVar; // slot 0 <- inserted
    uint256 public value;        // slot 1
    function setValue(uint256 v) external { value = v; }
}
