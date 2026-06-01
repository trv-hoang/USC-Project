// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Sc02V2 {
    address public newAdmin; // slot 0 (inserted)
    address public owner; // slot 1 (shifted)

    function setOwner(address o) external {
        require(o != address(0), "zero address");
        owner = o;
    }
}
