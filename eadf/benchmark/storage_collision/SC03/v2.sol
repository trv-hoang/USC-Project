// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Sc03V2 {
    address public value; // slot 0 (type changed uint256 -> address)

    function setValue(address v) external {
        require(v != address(0), "zero address");
        value = v;
    }
}
