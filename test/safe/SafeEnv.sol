// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";

import {IMulticall3} from "multicall/interfaces/IMulticall3.sol";

import {SafeProxyFactory} from "safe-wallet/proxies/SafeProxyFactory.sol";

import {MULTICALL3_ADDRESS, MULTICALL3_BYTECODE} from "src/artifacts/Multicall3Constants.sol";
import {
    SAFE_FACTORY_ADDRESS,
    SAFE_FACTORY_BYTECODE,
    SAFE_IMPLEMENTATION_ADDRESS,
    SAFE_IMPLEMENTATION_BYTECODE
} from "src/artifacts/SafeConstants.sol";

/// @author KONFeature
/// @title SafeEnv
/// @dev Contract used to provide the safe runtime env
contract SafeEnv is Test {
    /// @dev The multicall contract
    IMulticall3 internal _multicall;

    /// @dev The kernel factory that will be used for the test
    SafeProxyFactory internal _factory;

    /// @dev The safe that will be used for the test
    address internal _safeImplementation;

    /// @dev The safe beneficiary for refund
    address internal _safeRefundBeneficiary;

    /// @dev Setup safe environment
    function _setupSafeEnv() internal {
        // Setup the multicall contract
        vm.etch(MULTICALL3_ADDRESS, MULTICALL3_BYTECODE);
        vm.label(MULTICALL3_ADDRESS, "multicall3");
        _multicall = IMulticall3(MULTICALL3_ADDRESS);

        // Set initial safe implementation and factory
        vm.etch(SAFE_IMPLEMENTATION_ADDRESS, SAFE_IMPLEMENTATION_BYTECODE);
        vm.label(SAFE_IMPLEMENTATION_ADDRESS, "safeImplementation");
        _safeImplementation = SAFE_IMPLEMENTATION_ADDRESS;

        vm.etch(SAFE_FACTORY_ADDRESS, SAFE_FACTORY_BYTECODE);
        vm.label(SAFE_FACTORY_ADDRESS, "safeFactory");
        _factory = SafeProxyFactory(SAFE_FACTORY_ADDRESS);

        // Create the safe beneficiary
        _safeRefundBeneficiary = makeAddr("safeRefundBeneficiary");
    }
}
