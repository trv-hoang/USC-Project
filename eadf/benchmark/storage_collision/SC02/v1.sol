// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Sc02V1 {
    address public owner; // slot 0

    function setOwner(address o) external {
        require(o != address(0), "zero address");
        owner = o;
    }
}
