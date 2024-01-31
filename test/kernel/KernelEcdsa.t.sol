// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {GenericMainnetBenchmark} from "../GenericMainnetBenchmark.t.sol";

/// @dev Contract used to benchmark kernel ecdsa operations
/// @author KONFeature
contract KernelEcdsa is GenericMainnetBenchmark {
    function setUp() internal {
        _init();
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
        _deploymentData = _getDummyCallData();
        _deploymentFactory = address(_dummyContract);
    }

    /// @dev Encode the call data to be executed by the smart wallet
    /// @param _to The address of the contract to be called
    /// @param _data The execution data to be encoded
    function _encodeCallData(address _to, bytes memory _data)
        internal
        view
        virtual
        override
        returns (bytes memory _encodedCallData, address _entryPoint)
    {}
}
