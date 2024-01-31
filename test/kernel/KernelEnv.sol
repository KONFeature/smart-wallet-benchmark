// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";

import {KernelFactory} from "kernel/factory/KernelFactory.sol";

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE} from "I4337/artifacts/EntryPoint_0_6.sol";

import {
    KERNEL_FACTORY_ADDRESS,
    KERNEL_FACTORY_BYTECODE,
    KERNEL_IMPLEMENTATION_ADDRESS,
    KERNEL_IMPLEMENTATION_BYTECODE
} from "src/artifacts/KernelConstants.sol";

/// @author KONFeature
/// @title KernelEnv
/// @dev Contract used to provide the kernel runtime env
contract KernelEnv is Test {
    /// @dev The kernel factory that will be used for the test
    KernelFactory internal _factory;

    /// @dev The kernel impl that will be used for the test
    address internal _kernelImplementation;

    /// @dev The erc-4337 entrypoint that will be used for the test
    IEntryPoint internal _entryPoint;

    /// @dev The user op beneficiary
    address internal _userOpBeneficiary;

    /// @dev The factory owner
    address internal _factoryOwner;

    /// @dev Setup safe environment
    function _setupKernelEnv() internal {
        _userOpBeneficiary = payable(makeAddr("userOpBeneficiary"));
        _factoryOwner = makeAddr("factoryOwner");

        // Init of the entry point
        vm.etch(ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE);
        _entryPoint = IEntryPoint(payable(ENTRYPOINT_0_6_ADDRESS));

        // Setup the factory
        vm.etch(KERNEL_FACTORY_ADDRESS, KERNEL_FACTORY_BYTECODE);
        _factory = KernelFactory(KERNEL_FACTORY_ADDRESS);

        // Set initial kernel implementation
        vm.etch(KERNEL_IMPLEMENTATION_ADDRESS, KERNEL_IMPLEMENTATION_BYTECODE);
        _kernelImplementation = KERNEL_IMPLEMENTATION_ADDRESS;

        // Allow the implementation
        vm.startPrank(_factory.owner());
        _factory.setImplementation(KERNEL_IMPLEMENTATION_ADDRESS, true);
        _factory.setEntryPoint(_entryPoint);
        vm.stopPrank();
    }
}
