// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Sm02V2 {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }

    function double(uint256 x) external pure returns (uint256) {
        return x * 2;
    }
}
