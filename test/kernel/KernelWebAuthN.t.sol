// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {console} from "forge-std/Console.sol";

import {GenericMainnetBenchmark} from "../GenericMainnetBenchmark.t.sol";

import {Kernel} from "kernel/Kernel.sol";
import {KernelFactory} from "kernel/factory/KernelFactory.sol";
import {IKernel} from "kernel/interfaces/IKernel.sol";
import {Operation} from "kernel/common/Enums.sol";
import {IKernelValidator} from "kernel/interfaces/IKernelValidator.sol";
import {WebAuthnFclValidator} from "kernel/validator/webauthn/WebAuthnFclValidator.sol";
import {WebAuthnFclVerifier} from "kernel/validator/webauthn/WebAuthnFclVerifier.sol";
import {ERC4337Utils} from "kernel/utils/ERC4337Utils.sol";
import {P256VerifierWrapper} from "kernel/utils/P256VerifierWrapper.sol";

import {FCL_ecdsa_utils} from "FCL/FCL_ecdsa_utils.sol";
import {Base64Url} from "FCL/utils/Base64Url.sol";

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE} from "I4337/artifacts/EntryPoint_0_6.sol";

using ERC4337Utils for IEntryPoint;
using ERC4337Utils for Kernel;

/// @dev Contract used to benchmark kernel webauthn operations
/// @dev todo : To be rly clean, we should use bytecode of deployed kernel factory, kernel account, and ecdsa validator
/// @author KONFeature
contract KernelWebAuthNBenchmark is GenericMainnetBenchmark {
    // Curve order (number of points)
    uint256 constant n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    /// @dev The kernel factory that will be used for the test
    KernelFactory private _factory;

    /// @dev The kernel impl that will be used for the test
    address private _kernelImplementation;

    /// @dev The erc-4337 entrypoint that will be used for the test
    IEntryPoint internal _entryPoint;

    /// @dev The current validator we will benchmark
    WebAuthnFclValidator private _webAuthnFclValidator;

    /// @dev The p256 sig wrapper we will use to validate the sig
    P256VerifierWrapper private _p256Wrapper;

    /// @dev Simple tester contract that will help us with sig manangement
    WebAuthNHelper private _webAuthNHelper;

    /// @dev the owner of the kernel wallet we will test
    uint256 private _ownerX;
    uint256 private _ownerY;
    uint256 private _ownerPrivateKey;

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

        // Deploy the webauthn validator
        _p256Wrapper = new P256VerifierWrapper();
        _webAuthnFclValidator = new WebAuthnFclValidator(address(_p256Wrapper));

        // Deploy our helper
        _webAuthNHelper = new WebAuthNHelper();

        // Create the webAuthN owner
        (, _ownerPrivateKey) = makeAddrAndKey("webAuthNOwner");
        (_ownerX, _ownerY) = _getPublicKey(_ownerPrivateKey);
    }

    /// @dev Get the current smart wallet name (will be used for the different outputs)
    function _getSmartWalletName() internal view virtual override returns (string memory) {
        return "kernelWebAuthN";
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
        bytes memory enableData = abi.encode(_ownerX, _ownerY);
        bytes memory initData = abi.encodeWithSelector(IKernel.initialize.selector, _webAuthnFclValidator, enableData);

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
        bytes memory enableData = abi.encode(_ownerX, _ownerY);
        bytes memory initData = abi.encodeWithSelector(IKernel.initialize.selector, _webAuthnFclValidator, enableData);

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
        bytes32 userOpHash = _entryPoint.getUserOpHash(userOperation);
        bytes memory signature = _generateWebAuthnSignature(_ownerPrivateKey, userOpHash);
        // Add it to the user op, and prepand  it with sudo mode
        userOperation.signature = abi.encodePacked(bytes4(0x00000000), signature);

        // Build an array of user ops for the entry point
        UserOperation[] memory userOperations = new UserOperation[](1);
        userOperations[0] = userOperation;

        // Prepare the call to execute
        _encodedCallData = abi.encodeWithSelector(IEntryPoint.handleOps.selector, userOperations, _userOpBeneficiary);
        _executor = address(_entryPoint);
    }

    /* -------------------------------------------------------------------------- */
    /*                             WebAuthN utilities                             */
    /* -------------------------------------------------------------------------- */

    /// @dev Generate a webauthn signature for the given `_hash` using the given `_privateKey`
    function _generateWebAuthnSignature(uint256 _privateKey, bytes32 _hash)
        internal
        view
        returns (bytes memory signature)
    {
        (bytes32 msgToSign, bytes memory authenticatorData, bytes memory clientData, uint256 clientChallengeDataOffset)
        = _prepapreWebAuthnMsg(_hash);

        // Get the signature
        (uint256 r, uint256 s) = _getP256Signature(_privateKey, msgToSign);
        uint256[2] memory rs = [r, s];

        // Return the signature
        return abi.encode(authenticatorData, clientData, clientChallengeDataOffset, rs);
    }

    /// @dev Prepare all the base data needed to perform a webauthn signature o n the given `_hash`
    function _prepapreWebAuthnMsg(bytes32 _hash)
        internal
        view
        returns (
            bytes32 msgToSign,
            bytes memory authenticatorData,
            bytes memory clientData,
            uint256 clientChallengeDataOffset
        )
    {
        // Base Mapping of the message
        bytes memory encodedChallenge = bytes(Base64Url.encode(abi.encodePacked(_hash)));

        // Prepare the authenticator data (from a real webauthn challenge)
        authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000";

        // Prepare the client data (starting from a real webauthn challenge, then replacing only the bytes needed for the challenge)
        bytes memory clientDataStart = hex"7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22";
        bytes memory clientDataEnd =
            hex"222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a33303032222c2263726f73734f726967696e223a66616c73657d";
        clientData = bytes.concat(clientDataStart, encodedChallenge, clientDataEnd);
        clientChallengeDataOffset = 36;

        // Build the signature layout
        WebAuthnFclVerifier.FclSignatureLayout memory sigLayout = WebAuthnFclVerifier.FclSignatureLayout({
            authenticatorData: authenticatorData,
            clientData: clientData,
            challengeOffset: clientChallengeDataOffset,
            // R/S not needed since the formatter will only use the other data
            rs: [uint256(0), uint256(0)]
        });

        // Format it
        msgToSign = _webAuthNHelper.formatSigLayout(_hash, sigLayout);
    }

    /// @dev Get a public key for a p256 user, from the given `_privateKey`
    function _getPublicKey(uint256 _privateKey) internal view returns (uint256, uint256) {
        return FCL_ecdsa_utils.ecdsa_derivKpub(_privateKey);
    }

    /// @dev Generate a p256 signature, from the given `_privateKey` on the given `_hash`
    function _getP256Signature(uint256 _privateKey, bytes32 _hash) internal pure returns (uint256, uint256) {
        // Generate the signature using the k value and the private key
        (bytes32 r, bytes32 s) = vm.signP256(_privateKey, _hash);
        return (uint256(r), uint256(s));
    }
}

/// @dev simple contract to format a webauthn challenge (using to convert stuff in memory during test to calldata)
contract WebAuthNHelper {
    function formatSigLayout(bytes32 _hash, WebAuthnFclVerifier.FclSignatureLayout calldata signatureLayout)
        public
        view
        returns (bytes32)
    {
        console.log("hash: %d", uint256(_hash));
        return WebAuthnFclVerifier._formatWebAuthNChallenge(_hash, signatureLayout);
    }
}
