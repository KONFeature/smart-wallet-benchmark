// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/Console.sol";
import {LibString} from "solady/utils/LibString.sol";

import {MainnetMetering} from "gas-metering/MainnetMetering.sol";

/// @dev Generic test contract for benchmark smart wallets
/// @author KONFeature
abstract contract GenericMainnetBenchmark is MainnetMetering, Test {
    /// @dev The JSON output of the benchmark
    string private _jsonOutput;

    /// @dev dummy contract we will use to test user op
    /// todo: should be marked internal to prevent benchmarked conract to update it
    DummyContract internal _dummyContract;

    /// @dev The base smart wallet address that will be used
    /// todo: Should it be novzd in a modifier to managed test per test deployment of it?
    address private _baseSmartWallet;

    /// @dev Init the base stuff required to run the benchmark
    function _init() internal {
        // Prepare for gas mettering
        setUpMetering({verbose: false});

        // Deploy the dummy contract that will be used to test user op
        _dummyContract = new DummyContract();
    }

    /* -------------------------------------------------------------------------- */
    /*                              Abstract methods                              */
    /* -------------------------------------------------------------------------- */

    /// @dev Get the current smart wallet name (will be used for the different outputs)
    function _getSmartWalletName() internal view virtual returns (string memory);

    /// @dev Top level method used to create the smart wallet
    /// @param _salt The salt used to create the smart wallet, could be used during fuzz testing
    /// todo: Check the usefullness of the salt
    /// @return _deploymentData The encoded data that will be used to deploy the smart wallet
    /// @return _deploymentFactory The factory that will be used to deploy the smart wallet
    function _encodeCreateSmartWallet(bytes32 _salt)
        internal
        view
        virtual
        returns (bytes memory _deploymentData, address _deploymentFactory);

    /// @dev Encode the call data to be executed by the smart wallet
    /// @param _to The address of the contract to be called
    /// @param _data The execution data to be encoded
    /// @return _encodedCallData The encoded call data
    /// @return _entryPoint The entry point to execute this encoded call data
    function _encodeCallData(address _to, bytes memory _data)
        internal
        view
        virtual
        returns (bytes memory _encodedCallData, address _entryPoint);

    /* -------------------------------------------------------------------------- */
    /*                        Test smart wallet deployment                        */
    /* -------------------------------------------------------------------------- */

    /// @dev Test a simple call to the dummy contract for reference in the json
    function test_dummy() public manuallyMetered {
        // Get the call data
        bytes memory _dummyData = _getDummyCallData();

        // Meter the deployment
        (uint256 gasConsumed,) = meterCall({
            from: address(0),
            to: address(_dummyContract),
            callData: _dummyData,
            value: 0,
            transaction: true,
            expectRevert: false
        });

        // Add the result to the output
        _addResult("dummyCall", gasConsumed);
    }

    /// @dev Test a simple smart wallet deployment
    function test_deploy() public manuallyMetered {
        // Get the call data
        (bytes memory _deployData, address _factory) = _encodeCreateSmartWallet(0x0);

        // Meter the deployment
        (uint256 gasConsumed,) = meterCall({
            from: address(0),
            to: address(_factory),
            callData: _deployData,
            value: 0,
            transaction: true,
            expectRevert: false
        });

        // Add the result to the output
        _addResult("deploy", gasConsumed);
    }

    /* -------------------------------------------------------------------------- */
    /*                             Execution utilities                            */
    /* -------------------------------------------------------------------------- */

    /// @dev Get the dummy call data
    function _getDummyCallData() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(DummyContract.doDummyShit.selector);
    }

    /* -------------------------------------------------------------------------- */
    /*                              Output utilities                              */
    /* -------------------------------------------------------------------------- */

    /// @dev Get the output file name
    function _getOutputFile() private view returns (string memory) {
        return string.concat("./gas/", _getSmartWalletName(), ".json");
    }

    /// @dev Init the json file that will be used for the output
    function _addResult(string memory _testCase, uint256 _gasUsed) private {
        bool _isWriteOutputEnabled = vm.envOr("WRITE_BENCHMARK_RESULT", false);
        if (!_isWriteOutputEnabled) {
            console.log("- case: %s", _testCase);
            console.log("    gas : ", _gasUsed);
            return;
        }
        // Get the writer key
        string memory writerKey = _getSmartWalletName();

        // Check if the file exist
        string memory outputFile = _getOutputFile();

        if (!vm.exists(outputFile)) {
            // Create the file and write our full json
            string memory newJsonEntry = vm.serializeUint(writerKey, _testCase, _gasUsed);
            vm.writeJson(newJsonEntry, outputFile);
            return;
        }

        // Otherwise, check if the key exist in the file
        string memory jsonContent = vm.readFile(outputFile);
        string memory jsonKey = string.concat(".", _testCase);

        if (vm.keyExists(jsonContent, jsonKey)) {
            // Only replace the value inside the file if the key already exist
            vm.writeJson(LibString.toString(_gasUsed), outputFile, jsonKey);
            return;
        } else {
            // Otherwise, read the json, add the key, and write it back
            // todo: more efficient way to do this? 
            string memory writerCreatorKey = string.concat(writerKey, "-", _testCase, ".keyCreator");
            vm.serializeJson(writerCreatorKey, jsonContent);
            string memory newJsonEntry = vm.serializeUint(writerCreatorKey, _testCase, _gasUsed);
            vm.writeJson(newJsonEntry, outputFile);
        }
    }
}

/// @dev Dummy contract used to test the validator
contract DummyContract {
    function doDummyShit() public pure {
        bytes32 randomHash = keccak256("0xacab");
        bytes memory randomData = abi.encodePacked(randomHash);
        randomHash = keccak256(randomData);
    }
}
