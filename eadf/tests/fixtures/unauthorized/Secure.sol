// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract Secure {
    modifier onlyOwner() { _; }
    function _authorizeUpgrade(address /* newImpl */) internal onlyOwner {}
}
