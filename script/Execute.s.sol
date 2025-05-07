// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {ECDSA} from "@openzeppelin/utils/cryptography/ECDSA.sol";
import {Multisig} from "../src/Multisig.sol";

/// @title Execute
/// @notice Script to execute a transaction with collected signatures
contract Execute is Script {
    function run() external {
        /* --- mandatory env vars ----------------------------------- */
        uint256 deployerPk = vm.envUint("DEPLOYER_PK");
        address payable msigAddr = payable(vm.envAddress("MSIG"));
        Multisig ms = Multisig(msigAddr);

        address target = vm.envAddress("TARGET");
        uint256 value = vm.envUint("VALUE");
        bytes memory data = vm.envBytes("DATA");
        uint256 deadline = vm.envUint("DEADLINE");

        /* --- signatures (exactly two) ----------------------------- */
        bytes memory sigA = vm.envBytes("SIG_A");
        bytes memory sigB = vm.envBytes("SIG_B");
        require(sigA.length == 65 && sigB.length == 65, "Need two 65-byte sigs");

        /* --- sort them by signer address -------------------------- */
        bytes32 digest = ms.hashExecute(target, value, data, ms.nonce(), deadline);

        address signerA = ECDSA.recover(digest, sigA);
        address signerB = ECDSA.recover(digest, sigB);

        bytes[] memory sigs = new bytes[](2);
        if (signerA < signerB) {
            sigs[0] = sigA;
            sigs[1] = sigB;
        } else {
            sigs[0] = sigB;
            sigs[1] = sigA;
        }

        /* --- broadcast -------------------------------------------- */
        vm.startBroadcast(deployerPk);
        ms.execute(target, value, data, deadline, sigs);
        vm.stopBroadcast();
    }
}
