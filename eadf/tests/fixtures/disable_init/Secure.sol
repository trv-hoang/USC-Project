// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal upgradeable-style contract WITH _disableInitializers in ctor.
contract Secure {
    bool private _initialized;
    bool private _initializing;

    modifier initializer() {
        require(!_initialized, "initialized");
        _initialized = true;
        _;
    }

    function _disableInitializers() internal {
        _initialized = true;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize() public initializer {}
}
