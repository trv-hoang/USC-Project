// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

// V1: unguarded.
contract In03V1 is Initializable, OwnableUpgradeable {
    uint256 public value;

    function initialize() public initializer {
        __Ownable_init(msg.sender);
    }

    function setValue(uint256 v) public onlyOwner {
        value = v;
    }
}
