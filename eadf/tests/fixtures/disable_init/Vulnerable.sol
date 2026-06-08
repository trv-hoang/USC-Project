// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal upgradeable-style contract WITHOUT _disableInitializers in ctor.
/// Locally-defined `initializer` modifier to keep the fixture self-contained.
contract Vulnerable {
    bool private _initialized;

    modifier initializer() {
        require(!_initialized, "initialized");
        _initialized = true;
        _;
    }

    function initialize() public initializer {}
}
