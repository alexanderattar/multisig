// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IMultisig
/// @notice Interface for the Multisig contract, defining the core functionality
interface IMultisig {
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 deadline,
        bytes[] calldata sigs
    ) external returns (bytes memory);
    function updateSigners(
        address[] calldata newSigners,
        uint256 newThreshold,
        uint256 deadline,
        bytes[] calldata sigs
    ) external;
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}
