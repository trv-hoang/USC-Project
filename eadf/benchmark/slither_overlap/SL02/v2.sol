// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Sl02V2 {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }

    // VULN: delegatecall to a caller-controlled target.
    function exec(address target, bytes calldata data) external {
        (bool success,) = target.delegatecall(data);
        require(success, "call failed");
    }
}
