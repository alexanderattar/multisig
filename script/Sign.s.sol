// SPDX‑License‑Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Script.sol";

/// @title Sign
/// @notice Script to sign transaction digests for the multisig
contract Sign is Script {
    function run() external {
        bytes32 digest = vm.envBytes32("DIGEST");
        uint256 privateKey = vm.envUint("SIGNER_PK");

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        console2.log("Signed digest:");
        console2.logBytes32(digest);
        console2.log("Signer:", vm.addr(privateKey));
        console2.log("Signature (hex):");
        console2.logBytes(signature);
    }
}
