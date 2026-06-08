// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MiniCleanV2 {
    uint256 public value; // slot 0 (unchanged layout)
    function setValue(uint256 newValue) external { value = newValue; } // cosmetic rename
}
