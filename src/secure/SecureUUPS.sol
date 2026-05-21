// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/// @notice SECURE — _authorizeUpgrade is gated by onlyOwner.
contract SecureUUPS is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    uint256 public value;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); }

    // OZ v5: UUPSUpgradeable is stateless (no init); Ownable requires explicit owner.
    function initialize(address initialOwner) public initializer {
        __Ownable_init(initialOwner);
    }

    function setValue(uint256 _v) external { value = _v; }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
