// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {console} from "forge-std/Console.sol";

import {GenericMainnetBenchmark} from "../GenericMainnetBenchmark.t.sol";

import {SafeProxyFactory} from "safe-wallet/proxies/SafeProxyFactory.sol";
import {Safe} from "safe-wallet/Safe.sol";
import {Enum} from "safe-wallet/common/Enum.sol";

/// @dev Contract used to benchmark safe operations
/// @dev todo : To be rly clean, we should use bytecode of deployed safe and safe proxy
/// @author KONFeature
contract SafeBenchmark is GenericMainnetBenchmark {
    /// @dev The kernel factory that will be used for the test
    SafeProxyFactory private _factory;

    /// @dev The safe implementation that will be used for the test
    address private _safeImplementation;

    /// @dev the owner of the kernel wallet we will test
    address private _safeOwner;
    uint256 private _safeOwnerKey;

    /// @dev The safe beneficiary
    address private _safeRefundBeneficiary;

    function setUp() public {
        _init();

        // Deploy initial kernel implementation and factory
        _safeImplementation = address(new Safe());
        _factory = new SafeProxyFactory();

        // Create the ecdsa owner
        (_safeOwner, _safeOwnerKey) = makeAddrAndKey("safeOwner");

        // Create the safe beneficiary
        _safeRefundBeneficiary = makeAddr("safeRefundBeneficiary");
    }

    /// @dev Get the current smart wallet name (will be used for the different outputs)
    function _getSmartWalletName() internal view virtual override returns (string memory) {
        return "safe";
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
        // Build the owner array
        address[] memory _owners = new address[](1);
        _owners[0] = _safeOwner;

        // Build the data used to setup the safe wallet
        bytes memory setupData = abi.encodeWithSelector(
            Safe.setup.selector, _owners, 1, address(0), "", address(0), address(0), 0, address(0)
        );

        // Then encode the proxy call used to deploy the data
        _deploymentData = abi.encodeWithSelector(
            SafeProxyFactory.createProxyWithNonce.selector, _safeImplementation, setupData, uint256(_salt)
        );
        _deploymentFactory = address(_factory);
    }

    /// @dev Top level method used to create the smart wallet
    /// @param _salt The salt used to create the smart wallet, could be used during fuzz testing
    /// @return _smartWallet The address of the deployed smart wallet
    function _createSmartWallet(bytes32 _salt) internal virtual override returns (address _smartWallet) {
        // Build the owner array
        address[] memory _owners = new address[](1);
        _owners[0] = _safeOwner;

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
        view
        virtual
        override
        returns (bytes memory _encodedCallData, address _executor)
    {
        // TODO: Signasture generation?
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
            _safeRefundBeneficiary,
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
            _safeRefundBeneficiary,
            _nonce
        );

        // Sign that hash with the owner key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_safeOwnerKey, keccak256(txData));
        // Return that stuff packed
        signature = abi.encodePacked(r, s, v);
    }
}
