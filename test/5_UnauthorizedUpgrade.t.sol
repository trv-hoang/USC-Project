// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {VulnerableUUPS} from "../src/vulnerable/VulnerableUUPS.sol";
import {SecureUUPS} from "../src/secure/SecureUUPS.sol";
import {MaliciousImpl} from "../src/vulnerable/MaliciousImpl.sol";

contract UnauthorizedUpgradeTest is Test {
    address alice = address(0xA11CE);
    address payable bob = payable(address(0xB0B));

    function setUp() public {
        vm.deal(alice, 10 ether);
        vm.deal(bob, 0);
    }

    function testVulnerable_AnyoneCanUpgrade() public {
        // Deploy V1 logic and proxy; fund proxy with 10 ETH.
        VulnerableUUPS logic = new VulnerableUUPS();
        ERC1967Proxy proxy =
            new ERC1967Proxy(address(logic), abi.encodeWithSelector(VulnerableUUPS.initialize.selector));
        vm.deal(address(proxy), 10 ether);

        // Attacker deploys malicious impl and upgrades the proxy (no auth).
        vm.startPrank(bob);
        MaliciousImpl mal = new MaliciousImpl();
        VulnerableUUPS(payable(address(proxy))).upgradeToAndCall(address(mal), "");
        MaliciousImpl(payable(address(proxy))).drainFunds(bob);
        vm.stopPrank();

        assertEq(bob.balance, 10 ether, "attacker should have drained 10 ETH");
        assertEq(address(proxy).balance, 0, "proxy should be empty");
    }

    function testSecure_NonOwnerUpgradeReverts() public {
        SecureUUPS logic = new SecureUUPS();
        ERC1967Proxy proxy =
            new ERC1967Proxy(address(logic), abi.encodeWithSelector(SecureUUPS.initialize.selector, alice));

        vm.startPrank(bob);
        MaliciousImpl mal = new MaliciousImpl();
        vm.expectRevert(); // OwnableUnauthorizedAccount(bob)
        SecureUUPS(payable(address(proxy))).upgradeToAndCall(address(mal), "");
        vm.stopPrank();
    }

    function testSecure_OwnerCanUpgrade() public {
        SecureUUPS logic = new SecureUUPS();
        ERC1967Proxy proxy =
            new ERC1967Proxy(address(logic), abi.encodeWithSelector(SecureUUPS.initialize.selector, alice));

        vm.startPrank(alice);
        SecureUUPS v2 = new SecureUUPS();
        SecureUUPS(payable(address(proxy))).upgradeToAndCall(address(v2), "");
        vm.stopPrank();
        // No revert = pass.
    }
}
