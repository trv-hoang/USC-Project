// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract Vulnerable {
    function _authorizeUpgrade(address /* newImpl */) internal { /* no modifier */ }
}
