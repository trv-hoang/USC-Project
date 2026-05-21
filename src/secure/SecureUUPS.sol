// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/**
 * @title SecureUUPS
 * @notice SECURE: UUPS implementation whose upgrade authorization is gated by onlyOwner.
 * @dev The secure counterpart to {VulnerableUUPS} (Scenario 3 — Unauthorized Upgrade).
 *
 * SECURITY FEATURES:
 * 1. constructor() calls _disableInitializers() — prevents direct initialization
 *    of the implementation contract (defence-in-depth, even though the proxy
 *    pattern itself blocks most direct calls)
 * 2. _authorizeUpgrade is gated by onlyOwner — only the contract owner can
 *    authorise replacing the implementation
 * 3. Uses Initializable pattern with the `initializer` modifier
 * 4. Inherits OwnableUpgradeable for owner-based access control
 *
 * Compare with {VulnerableUUPS}: same surface, but every upgrade attempt by a
 * non-owner reverts with OwnableUnauthorizedAccount(caller).
 */
contract SecureUUPS is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    /// @notice Counter value (storage slot 0).
    uint256 public value;

    /**
     * @notice CRITICAL: Disable initializers in the implementation contract.
     * @dev Prevents attackers from calling initialize() on the implementation
     *      directly (in addition to upgrade-path protection).
     * @custom:oz-upgrades-unsafe-allow constructor
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the contract (called once via proxy).
     * @param initialOwner The address that will own the proxy.
     * @dev OZ v5: UUPSUpgradeable is @custom:stateless (no __UUPSUpgradeable_init).
     *      Ownable requires an explicit initial owner argument.
     */
    function initialize(address initialOwner) public initializer {
        __Ownable_init(initialOwner);
    }

    /**
     * @notice Set the counter value.
     * @param _v New value to set.
     */
    function setValue(uint256 _v) external {
        value = _v;
    }

    /**
     * @notice Authorization check for upgrades.
     * @dev Only owner can upgrade — closes the Scenario 3 vulnerability.
     */
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
