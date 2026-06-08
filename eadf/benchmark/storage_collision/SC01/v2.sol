// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Sc01V2 {
    uint256 public collisionVar; // slot 0 (inserted)
    uint256 public value; // slot 1 (shifted)

    function setValue(uint256 v) external {
        value = v;
    }

    function setCollisionVar(uint256 c) external {
        collisionVar = c;
    }
}
