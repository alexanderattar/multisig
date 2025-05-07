// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Script.sol";
import "src/Multisig.sol";

/// @title Propose
/// @notice Script to generate transaction proposals for the multisig
contract Propose is Script {
    function run() external view returns (bytes32 digest) {
        address payable msAddr = payable(vm.envAddress("MSIG"));
        Multisig ms = Multisig(msAddr);

        // Determine the type of proposal
        string memory txType = vm.envString("TX_TYPE"); // "execute" or "update"
        uint256 deadline = block.timestamp + 1 hours;

        if (keccak256(abi.encodePacked(txType)) == keccak256(abi.encodePacked("execute"))) {
            // For execute transactions
            address target = vm.envAddress("TARGET");
            uint256 value = vm.envUint("VALUE");
            bytes memory data = vm.envBytes("DATA");
            digest = ms.hashExecute(target, value, data, ms.nonce(), deadline);

            console2.log("Generated execute transaction digest:");
            console2.logBytes32(digest);
            console2.log("Target:", target);
            console2.log("Value:", value);
            console2.log("Deadline:", deadline);
            console2.log("Nonce:", ms.nonce());
        } else if (keccak256(abi.encodePacked(txType)) == keccak256(abi.encodePacked("update"))) {
            // For updateSigners transactions
            address[] memory newSigners = new address[](3);
            newSigners[0] = vm.addr(vm.envUint("NEW_A_PK"));
            newSigners[1] = vm.addr(vm.envUint("NEW_B_PK"));
            newSigners[2] = vm.addr(vm.envUint("NEW_C_PK"));
            uint256 newThreshold = vm.envUint("NEW_THRESHOLD");

            // Calculate the digest for updateSigners
            bytes32 typehash = keccak256(
                "Update(address[] newSigners,uint256 newThreshold,uint256 nonce,uint256 deadline)"
            );
            bytes32 digest = keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    ms.DOMAIN_SEPARATOR(),
                    keccak256(
                        abi.encode(
                            typehash,
                            keccak256(abi.encodePacked(newSigners)),
                            newThreshold,
                            ms.nonce(),
                            deadline
                        )
                    )
                )
            );

            console2.log("Generated updateSigners transaction digest:");
            console2.logBytes32(digest);
            console2.log("New threshold:", newThreshold);
            console2.log("Deadline:", deadline);
            console2.log("Nonce:", ms.nonce());
        }
    }
}
