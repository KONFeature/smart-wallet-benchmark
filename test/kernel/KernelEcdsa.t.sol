// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {console} from "forge-std/Console.sol";

import {GenericMainnetBenchmark} from "../GenericMainnetBenchmark.t.sol";

import {Kernel} from "kernel/Kernel.sol";
import {KernelFactory} from "kernel/factory/KernelFactory.sol";
import {IKernel} from "kernel/interfaces/IKernel.sol";
import {Operation} from "kernel/common/Enums.sol";
import {IKernelValidator} from "kernel/interfaces/IKernelValidator.sol";
import {ECDSAValidator} from "kernel/validator/ECDSAValidator.sol";
import {ERC4337Utils} from "kernel/utils/ERC4337Utils.sol";

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE} from "I4337/artifacts/EntryPoint_0_6.sol";

using ERC4337Utils for IEntryPoint;
using ERC4337Utils for Kernel;

/// @dev Contract used to benchmark kernel ecdsa operations
/// @dev todo : To be rly clean, we should use bytecode of deployed kernel factory, kernel account, and ecdsa validator
/// @author KONFeature
contract KernelEcdsa is GenericMainnetBenchmark {
    /// @dev The kernel factory that will be used for the test
    KernelFactory private _factory;

    /// @dev The kernel account that will be used for the test
    Kernel private _kernel;
    address private _kernelImplementation;

    /// @dev The erc-4337 entrypoint that will be used for the test
    IEntryPoint internal _entryPoint;

    /// @dev The current validator we will benchmark
    ECDSAValidator private _ecdsaValidator;

    /// @dev the owner of the kernel wallet we will test
    address private _ecdsaOwner;
    uint256 private _ecdsaOwnerKey;

    /// @dev The user op beneficiary
    address private _userOpBeneficiary;

    function setUp() public {
        _init();

        address factoryOwner = makeAddr("factoryOwner");
        _userOpBeneficiary = payable(makeAddr("userOpBeneficiary"));

        // Init of the entry point
        vm.etch(ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE);
        _entryPoint = IEntryPoint(payable(ENTRYPOINT_0_6_ADDRESS));

        // Deploy initial kernel implementation and factory
        _kernelImplementation = address(new Kernel(_entryPoint));
        _factory = new KernelFactory(factoryOwner, _entryPoint);

        // Allow the factory to create new kernel
        vm.prank(factoryOwner);
        _factory.setImplementation(_kernelImplementation, true);

        // Deploy the ecdsa validator
        _ecdsaValidator = new ECDSAValidator();

        // Create the ecdsa owner
        (_ecdsaOwner, _ecdsaOwnerKey) = makeAddrAndKey("ecdsaOwner");
    }

    /// @dev Get the current smart wallet name (will be used for the different outputs)
    function _getSmartWalletName() internal view virtual override returns (string memory) {
        return "kernelEcdsa";
    }

    /// @dev Top level method used to create the smart wallet
    /// @param _salt The salt used to create the smart wallet, could be used during fuzz testing
    /// todo: Check the usefullness of the salt
    function _encodeCreateSmartWallet(bytes32 _salt)
        internal
        view
        virtual
        override
        returns (bytes memory _deploymentData, address _deploymentFactory)
    {
        // Build the data used for the validator to enable the smart wallet
        bytes memory enableData = abi.encodePacked(_ecdsaOwner);
        bytes memory initData = abi.encodeWithSelector(IKernel.initialize.selector, _ecdsaValidator, enableData);

        // Then encode the proxy call used to deploy the data
        _deploymentData = abi.encodeWithSelector(
            KernelFactory.createAccount.selector, _kernelImplementation, initData, uint256(_salt)
        );
        _deploymentFactory = address(_factory);
    }

    /// @dev Top level method used to create the smart wallet
    /// @param _salt The salt used to create the smart wallet, could be used during fuzz testing
    /// @return _smartWallet The address of the deployed smart wallet
    function _createSmartWallet(bytes32 _salt) internal virtual override returns (address _smartWallet) {
        // Build the data used for the validator to enable the smart wallet
        bytes memory enableData = abi.encodePacked(_ecdsaOwner);
        bytes memory initData = abi.encodeWithSelector(IKernel.initialize.selector, _ecdsaValidator, enableData);

        // Deploy the wallet and return it's address
        _smartWallet = _factory.createAccount(_kernelImplementation, initData, uint256(_salt));

        // Add a few gas to the deployment
        vm.deal(_smartWallet, 100 ether);
    }

    /// @dev Encode the call data to be executed by the smart wallet
    /// @param _smartWallet The address of the smart wallet that will execute the call
    /// @param _to The address of the contract to be called
    /// @param _data The execution data to be encoded
    function _encodeCallData(address _smartWallet, address _to, bytes memory _data)
        internal
        view
        virtual
        override
        returns (bytes memory _encodedCallData, address _executor)
    {
        // Prepare the user operation
        bytes memory executeCallData =
            abi.encodeWithSelector(IKernel.execute.selector, address(_to), 0, _data, Operation.Call);
        UserOperation memory userOperation = _entryPoint.fillUserOp(address(_smartWallet), executeCallData);

        // Get the sig for this user op
        bytes memory signature = _entryPoint.signUserOpHash(vm, _ecdsaOwnerKey, userOperation);
        // Add it to the user op, and prepand  it with sudo mode
        userOperation.signature = abi.encodePacked(bytes4(0x00000000), signature);

        // Build an array of user ops for the entry point
        UserOperation[] memory userOperations = new UserOperation[](1);
        userOperations[0] = userOperation;

        // Prepare the call to execute
        _encodedCallData = abi.encodeWithSelector(IEntryPoint.handleOps.selector, userOperations, _userOpBeneficiary);
        _executor = address(_entryPoint);
    }
}
