// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title VulnerableUUPS
 * @notice VULNERABLE: UUPS implementation whose upgrade authorization is wide open.
 * @dev Demonstrates the "Unauthorized Upgrade" vulnerability (Scenario 3).
 *
 * VULNERABILITIES:
 * 1. _authorizeUpgrade has no access-control modifier — anyone can call
 *    upgradeToAndCall on the proxy and replace the implementation
 * 2. Constructor does NOT call _disableInitializers() — kept simple to
 *    isolate the access-control flaw demonstrated by Scenario 3
 *
 * ATTACK FLOW:
 *  Deploy proxy → fund proxy with ETH → attacker deploys MaliciousImpl →
 *  attacker calls proxy.upgradeToAndCall(MaliciousImpl, "") → succeeds because
 *  _authorizeUpgrade is a no-op → attacker calls drainFunds → proxy emptied.
 *
 * Compare with {SecureUUPS} which gates the same function with onlyOwner.
 */
contract VulnerableUUPS is Initializable, UUPSUpgradeable {
    /// @notice Counter value (storage slot 0). Preserved across the malicious upgrade.
    uint256 public value;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        /* no _disableInitializers — kept simple for Scenario 3 */
    }

    /**
     * @notice Initialize the implementation through the proxy.
     * @dev OZ v5: UUPSUpgradeable is @custom:stateless — no __UUPSUpgradeable_init() exists.
     *      The `initializer` modifier alone blocks re-initialization through the proxy.
     */
    function initialize() public initializer {}

    /**
     * @notice Set the counter value.
     * @param _v New value to set.
     */
    function setValue(uint256 _v) external {
        value = _v;
    }

    /**
     * @notice VULNERABILITY: missing onlyOwner — any caller can authorize an upgrade.
     * @dev Required by {UUPSUpgradeable}. In a secure contract this would be gated.
     */
    function _authorizeUpgrade(address) internal override {}
}
