// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title MockStorage
/// @notice Simple contract with a storage variable for testing arbitrary calls
contract MockStorage {
    uint256 private value;

    function setValue(uint256 newValue) external {
        value = newValue;
    }

    function getValue() external view returns (uint256) {
        return value;
    }
}
