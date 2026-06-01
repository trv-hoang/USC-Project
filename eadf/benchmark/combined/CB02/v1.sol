// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

// V1: open auth (vulnerable), single var.
contract Cb02V1 is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    uint256 public value; // slot 0

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize() public initializer {
        __Ownable_init(msg.sender);
    }

    function setValue(uint256 v) public onlyOwner {
        value = v;
    }

    function _authorizeUpgrade(address) internal override {}
}
