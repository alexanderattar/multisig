// SPDX‑License‑Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Script.sol";
import "src/Multisig.sol";

contract Deploy is Script {
    function run() external returns (Multisig ms) {
        // Get deployer private key
        uint256 deployerPk = vm.envUint("DEPLOYER_PK");
        // Start broadcast
        vm.startBroadcast(deployerPk);
        // Get signers
        address[] memory signers = new address[](3);
        signers[0] = vm.addr(vm.envUint("A_PK"));
        signers[1] = vm.addr(vm.envUint("B_PK"));
        signers[2] = vm.addr(vm.envUint("C_PK"));
        // Deploy multisig
        ms = new Multisig(signers, 2);

        // Fund multisig with 10 ETH so later execute() calls succeed
        (bool sent, ) = address(ms).call{value: 10 ether}("");
        require(sent, "Funding multisig failed");

        vm.stopBroadcast();
    }
}
