// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Sl02V1 {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }
}
