// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @notice VULNERABLE — _authorizeUpgrade is unguarded; ANY caller can upgrade.
contract VulnerableUUPS is Initializable, UUPSUpgradeable {
    uint256 public value;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { /* no _disableInitializers — kept simple for Scenario 3 */ }

    function initialize() public initializer {}

    function setValue(uint256 _v) external { value = _v; }

    // VULNERABILITY: missing onlyOwner — anyone can call upgradeToAndCall via the proxy
    function _authorizeUpgrade(address) internal override {}
}
