// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {console} from "forge-std/Console.sol";
import {IMulticall3} from "multicall/interfaces/IMulticall3.sol";

import {GenericMainnetBenchmark} from "../GenericMainnetBenchmark.t.sol";

import {SafeProxyFactory} from "safe-wallet/proxies/SafeProxyFactory.sol";
import {Safe} from "safe-wallet/Safe.sol";
import {Enum} from "safe-wallet/common/Enum.sol";

import {FCL_ecdsa_utils} from "FCL/FCL_ecdsa_utils.sol";
import {Base64Url} from "FCL/utils/Base64Url.sol";

import {WebAuthnFclVerifier} from "kernel/validator/webauthn/WebAuthnFclVerifier.sol";

import {
    P256_FACTORY_ADDRESS,
    P256_FACTORY_BYTECODE,
    P256_IMPLEMENTATION_ADDRESS,
    P256_IMPLEMENTATION_BYTECODE
} from "src/artifacts/P256Constants.sol";
import {SafeEnv} from "./SafeEnv.sol";

/// @title IP256SignerFactory
interface IP256SignerFactory {
    function create(uint256 x, uint256 y) external returns (address);
}

/// @dev Contract used to benchmark safe operations via cometh P256
/// @dev todo : To be rly clean, we should use bytecode of deployed safe and safe proxy
/// @author KONFeature
contract SafeComethBenchmark is GenericMainnetBenchmark, SafeEnv {
    /// @dev The cometh 256 signer factory
    IP256SignerFactory private _p256Factory;

    /// @dev The p256 signer implementation
    address private _p256Implementation;

    /// @dev the owner of the kernel wallet we will test
    address private _safeOwner;
    uint256 private _safeOwnerKey;

    /// @dev the owner of the kernel wallet we will test
    uint256 private _ownerX;
    uint256 private _ownerY;
    uint256 private _ownerPrivateKey;

    /// @dev The predicted signer address
    address _predictedSignerAddress;

    /// @dev Simple tester contract that will help us with sig manangement
    WebAuthNHelper private _webAuthNHelper;

    function setUp() public {
        _init();
        _setupSafeEnv();

        // Deploy our helper
        _webAuthNHelper = new WebAuthNHelper();

        // Init of the p256 factory
        vm.etch(P256_FACTORY_ADDRESS, P256_FACTORY_BYTECODE);
        _p256Factory = IP256SignerFactory(P256_FACTORY_ADDRESS);

        // Deploy initial p256 implementation and factory
        vm.etch(P256_IMPLEMENTATION_ADDRESS, P256_IMPLEMENTATION_BYTECODE);
        _p256Implementation = P256_IMPLEMENTATION_ADDRESS;

        // Create the ecdsa owner
        (_safeOwner, _safeOwnerKey) = makeAddrAndKey("safeOwner");

        // Create the webAuthN owner
        (, _ownerPrivateKey) = makeAddrAndKey("webAuthNOwner");
        (_ownerX, _ownerY) = _getPublicKey(_ownerPrivateKey);

        // TODO: Predict the p256 address
        // TODO: Better way to do that??
        uint256 snapshotId = vm.snapshot();
        vm.prank(address(_multicall));
        address predictedSignerAddress = _p256Factory.create(_ownerX, _ownerY);
        vm.revertTo(snapshotId);
        _predictedSignerAddress = predictedSignerAddress;
    }

    /// @dev Get the current smart wallet name (will be used for the different outputs)
    function _getSmartWalletName() internal view virtual override returns (string memory) {
        return "safeCometh";
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
        // TODO: We should predict the address here

        // Call data for the p256 creation
        bytes memory p256Creation = abi.encodeWithSelector(IP256SignerFactory.create.selector, _ownerX, _ownerY);

        // We need multicall with p256 and safe init
        // We need to predict the p256 salt
        // Build the owner array
        address[] memory _owners = new address[](1);
        _owners[0] = _predictedSignerAddress;

        // Build the data used to setup the safe wallet
        bytes memory setupData = abi.encodeWithSelector(
            Safe.setup.selector, _owners, 1, address(0), "", address(0), address(0), 0, address(0)
        );

        // Then encode the proxy call used to deploy the data
        bytes memory safeCreation = abi.encodeWithSelector(
            SafeProxyFactory.createProxyWithNonce.selector, _safeImplementation, setupData, uint256(_salt)
        );
        _deploymentFactory = address(_factory);

        // Prepare the 2 call
        IMulticall3.Call[] memory calls = new IMulticall3.Call[](2);
        calls[0] = IMulticall3.Call({target: address(_p256Factory), callData: p256Creation});
        calls[1] = IMulticall3.Call({target: address(_factory), callData: safeCreation});

        // Return the bundle call data
        _deploymentData = abi.encodeWithSelector(IMulticall3.aggregate.selector, calls);
        _deploymentFactory = address(_multicall);
    }

    /// @dev Top level method used to create the smart wallet
    /// @param _salt The salt used to create the smart wallet, could be used during fuzz testing
    /// @return _smartWallet The address of the deployed smart wallet
    function _createSmartWallet(bytes32 _salt) internal virtual override returns (address _smartWallet) {
        // Create the p256 signer
        address p256Signer = _p256Factory.create(_ownerX, _ownerY);
        vm.label(p256Signer, "p256Signer");

        // Build the owner array
        address[] memory _owners = new address[](1);
        _owners[0] = p256Signer;

        // Build the data used to setup the safe wallet
        bytes memory setupData = abi.encodeWithSelector(
            Safe.setup.selector, _owners, 1, address(0), "", address(0), address(0), 0, address(0)
        );

        // Deploy the wallet and return it's address
        _smartWallet = address(_factory.createProxyWithNonce(_safeImplementation, setupData, uint256(_salt)));

        // Add a few gas to the deployment
        vm.deal(_smartWallet, 100 ether);
    }

    /// @dev Encode the call data to be executed by the smart wallet
    /// @param _smartWallet The address of the smart wallet that will execute the call
    /// @param _to The address of the contract to be called
    /// @param _data The execution data to be encoded
    function _encodeCallData(address _smartWallet, address _to, bytes memory _data)
        internal
        virtual
        override
        returns (bytes memory _encodedCallData, address _executor)
    {
        // Generate a signature for this transaction
        bytes memory signature = _generateSignature(payable(_smartWallet), _to, _data);

        // Encode the execute transaction call
        _encodedCallData = abi.encodeWithSelector(
            Safe.execTransaction.selector,
            _to,
            0,
            _data,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            address(0),
            signature
        );
        _executor = _smartWallet;
    }

    /// @dev Generate the signature for a safe transaction
    function _generateSignature(address payable _smartWallet, address _to, bytes memory _data)
        private
        view
        returns (bytes memory signature)
    {
        // Get the current safe nonce
        uint256 _nonce = Safe(_smartWallet).nonce();
        // TODO: Create EIP-712 typed data????
        // TODO: Sign this typed data via webauthn

        // Build the safe tx hash
        bytes memory txData = Safe(_smartWallet).encodeTransactionData(
            _to,
            0, // value
            _data,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            address(0),
            _nonce
        );

        // Sign that hash with the owner key
        bytes memory rawWebAuthNSignature = _generateWebAuthnSignature(_ownerPrivateKey, keccak256(txData));

        // Return a formatted signature for the safe
        signature = _formatContractSigForSafe(_predictedSignerAddress, rawWebAuthNSignature);
    }

    /// @dev format the signature for the safe
    /// @dev similar to TS method: `formatWebAuthnSignatureForSafe` from their SDK
    function _formatContractSigForSafe(address _signer, bytes memory _signature) internal view returns (bytes memory) {
        // Build the verifier and data position var
        bytes memory verifierAndDataPosition = abi.encode(_signer, uint256(65));

        // Get the signature length
        uint256 signatureLength = _signature.length;

        // The signature type (0 to specify it's a contract signature)
        // todo: uint8 or uint16?
        uint8 signatureType = 0;

        // Return the packed stuff
        return abi.encodePacked(verifierAndDataPosition, signatureType, signatureLength, _signature);
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

        // Return the signature (same layout as `SignatureLayout` used in the `P256Signer`)
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

    /// @dev Generate a p256 signature, from the given `_privateKey` on the given `_hash`
    function _getP256Signature(uint256 _privateKey, bytes32 _hash) internal pure returns (uint256, uint256) {
        // Generate the signature using the k value and the private key
        (bytes32 r, bytes32 s) = vm.signP256(_privateKey, _hash);
        return (uint256(r), uint256(s));
    }

    /// @dev Get a public key for a p256 user, from the given `_privateKey`
    function _getPublicKey(uint256 _privateKey) internal view returns (uint256, uint256) {
        return FCL_ecdsa_utils.ecdsa_derivKpub(_privateKey);
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
