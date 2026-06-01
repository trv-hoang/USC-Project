// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

// V2: drops the constructor guard — introduces the vulnerability.
contract In02V2 is Initializable, OwnableUpgradeable {
    uint256 public value;

    function initialize() public initializer {
        __Ownable_init(msg.sender);
    }

    function setValue(uint256 v) public onlyOwner {
        value = v;
    }

    function bump() public onlyOwner {
        value += 1;
    }
}
