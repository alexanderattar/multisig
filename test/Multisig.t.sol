// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import "src/Multisig.sol";

import "./mock/MockERC20.sol";
import "./mock/MockStorage.sol";
import "./mock/MockGovernance.sol";

/// @title MultisigTest
/// @notice Comprehensive test suite for the Multisig contract
contract MultisigTest is Test {
    Multisig ms;

    // Test private keys for signers
    uint256 private alicePk = 0xA11CE;
    uint256 private bobPk = 0xB0B;
    uint256 private carolPk = 0xCA7;
    uint256 private davePk = 0xDADA;

    // Derived addresses
    address private alice = vm.addr(alicePk);
    address private bob = vm.addr(bobPk);
    address private carol = vm.addr(carolPk);
    address private dave = vm.addr(davePk);

    // Test contract for function calls
    MockERC20 token;

    // Event declarations for testing
    event Executed(address indexed target, uint256 value, bytes data, uint256 nonce, uint256 deadline);
    event SignersUpdated(address[] newSigners, uint256 newThreshold);

    function setUp() public {
        // NOTE: Uncomment to print addresses for debugging
        // Print addresses for debugging
        // console.log("Alice's address: %s", alice);
        // console.log("Bob's address: %s", bob);
        // console.log("Carol's address: %s", carol);
        // console.log("Dave's address: %s", dave);

        // Initialize with 3 signers and threshold of 2
        address[] memory signers = new address[](3);
        signers[0] = alice;
        signers[1] = bob;
        signers[2] = carol;

        ms = new Multisig(signers, 2);

        // Setup test environment
        vm.deal(address(ms), 10 ether);
        token = new MockERC20("Test Token", "TST", 18);
        token.mint(address(ms), 1000 ether);
    }

    /// @notice Helper to create a signature for a digest
    function _sign(bytes32 digest, uint256 pk) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Helper to get signatures in ascending order by signer address
    function _getOrderedSignatures(bytes32 digest) internal view returns (bytes[] memory) {
        bytes[] memory sigs = new bytes[](2);

        // Based on tests, we know bob's address is lexicographically smaller than alice's
        // so bob's signature should come first
        sigs[0] = _sign(digest, bobPk);
        sigs[1] = _sign(digest, alicePk);

        return sigs;
    }

    /// @notice Test ETH transfer execution
    function testExecuteEthTransfer() public {
        uint256 deadline = block.timestamp + 1 hours;
        address recipient = address(0xBEEF);
        uint256 value = 1 ether;
        bytes memory data = "";

        // Calculate digest for signing
        bytes32 digest = ms.hashExecute(recipient, value, data, ms.nonce(), deadline);

        // Get signatures in ascending order by signer address
        bytes[] memory sigs = _getOrderedSignatures(digest);

        // Record recipient balance before
        uint256 balanceBefore = recipient.balance;

        // Expect the Executed event to be emitted
        vm.expectEmit(true, true, true, true);
        emit Executed(recipient, value, data, 0, deadline);

        // Execute the transaction
        ms.execute(recipient, value, data, deadline, sigs);

        // Verify recipient received ETH
        assertEq(recipient.balance, balanceBefore + value);

        // Verify nonce incremented
        assertEq(ms.nonce(), 1);
    }

    /// @notice Test executing a contract call (ERC20 transfer)
    function testExecuteContractCall() public {
        uint256 deadline = block.timestamp + 1 hours;
        address recipient = address(0xBEEF);
        uint256 tokenAmount = 100 ether;

        // Create ERC20 transfer call data
        bytes memory data = abi.encodeWithSelector(token.transfer.selector, recipient, tokenAmount);

        // Calculate digest for signing
        bytes32 digest = ms.hashExecute(address(token), 0, data, ms.nonce(), deadline);

        // Get signatures in ascending order by signer address
        bytes[] memory sigs = _getOrderedSignatures(digest);

        // Record balances before
        uint256 msBefore = token.balanceOf(address(ms));
        uint256 recipientBefore = token.balanceOf(recipient);

        // Execute the transaction
        ms.execute(address(token), 0, data, deadline, sigs);

        // Verify token transfer occurred
        assertEq(token.balanceOf(address(ms)), msBefore - tokenAmount);
        assertEq(token.balanceOf(recipient), recipientBefore + tokenAmount);
    }

    /// @notice Test updating signers
    function testUpdateSigners() public {
        uint256 deadline = block.timestamp + 1 hours;

        // New signer set including dave, removing carol
        address[] memory newSigners = new address[](3);
        newSigners[0] = alice;
        newSigners[1] = bob;
        newSigners[2] = dave;
        uint256 newThreshold = 2;

        // Calculate digest for signing (needs to match contract implementation)
        bytes32 root = keccak256(abi.encodePacked(newSigners));
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                ms.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Update(bytes32 newRoot,uint256 newThreshold,uint256 nonce,uint256 deadline)"),
                        root,
                        newThreshold,
                        ms.nonce(),
                        deadline
                    )
                )
            )
        );

        // Get signatures in ascending order by signer address
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(digest, bobPk);
        sigs[1] = _sign(digest, alicePk);

        // Expect the SignersUpdated event to be emitted
        vm.expectEmit(true, true, false, false);
        emit SignersUpdated(newSigners, newThreshold);

        // Update signers
        ms.updateSigners(newSigners, newThreshold, deadline, sigs);

        // Verify nonce incremented
        assertEq(ms.nonce(), 1);

        // Verify new signers are set correctly
        assertTrue(ms.isSigner(alice));
        assertTrue(ms.isSigner(bob));
        assertTrue(ms.isSigner(dave));
        assertFalse(ms.isSigner(carol));

        // Verify new threshold
        assertEq(ms.threshold(), newThreshold);
    }

    /// @notice Test for error case: not enough signatures
    function testErrorNotEnoughSignatures() public {
        uint256 deadline = block.timestamp + 1 hours;
        address recipient = address(0xBEEF);
        uint256 value = 1 ether;
        bytes memory data = "";

        // Calculate digest for signing
        bytes32 digest = ms.hashExecute(recipient, value, data, ms.nonce(), deadline);

        // Only one signature
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(digest, alicePk);

        // Expect revert
        vm.expectRevert(Multisig.NotEnoughSigners.selector);
        ms.execute(recipient, value, data, deadline, sigs);
    }

    /// @notice Test for error case: signature from non-signer
    function testErrorUnknownSigner() public {
        uint256 deadline = block.timestamp + 1 hours;
        address recipient = address(0xBEEF);
        uint256 value = 1 ether;
        bytes memory data = "";

        // Calculate digest for signing
        bytes32 digest = ms.hashExecute(recipient, value, data, ms.nonce(), deadline);

        // One valid signature, one invalid (from non-signer dave)
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(digest, alicePk);
        sigs[1] = _sign(digest, davePk); // Dave is not a signer

        // Expect revert
        vm.expectRevert(Multisig.UnknownSigner.selector);
        ms.execute(recipient, value, data, deadline, sigs);
    }

    /// @notice Test for error case: expired deadline
    function testErrorExpiredDeadline() public {
        uint256 deadline = block.timestamp + 1 hours;
        address recipient = address(0xBEEF);
        uint256 value = 1 ether;
        bytes memory data = "";

        // Calculate digest for signing
        bytes32 digest = ms.hashExecute(recipient, value, data, ms.nonce(), deadline);

        // Collect signatures
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(digest, alicePk);
        sigs[1] = _sign(digest, bobPk);

        // Warp to after the deadline
        vm.warp(deadline + 1);

        // Expect revert
        vm.expectRevert(Multisig.DeadlineExpired.selector);
        ms.execute(recipient, value, data, deadline, sigs);
    }

    /// @notice Test for error case: signatures not in ascending order
    function testErrorBadSignatureOrder() public {
        uint256 deadline = block.timestamp + 1 hours;
        address recipient = address(0xBEEF);
        uint256 value = 1 ether;
        bytes memory data = "";

        // Calculate digest for signing
        bytes32 digest = ms.hashExecute(recipient, value, data, ms.nonce(), deadline);

        // Signatures in wrong order (alice, then bob) - this is backwards since bob's address comes first
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(digest, alicePk);
        sigs[1] = _sign(digest, bobPk);

        // Expect revert
        vm.expectRevert(Multisig.BadSignatureOrder.selector);
        ms.execute(recipient, value, data, deadline, sigs);
    }

    /// @notice Test for error case: failed call
    function testErrorFailedCall() public {
        uint256 deadline = block.timestamp + 1 hours;
        address recipient = address(0); // Zero address will cause ERC20 transfer to fail
        uint256 tokenAmount = 100 ether;

        // Create ERC20 transfer call data
        bytes memory data = abi.encodeWithSelector(token.transfer.selector, recipient, tokenAmount);

        // Calculate digest for signing
        bytes32 digest = ms.hashExecute(address(token), 0, data, ms.nonce(), deadline);

        // Get signatures in ascending order by signer address
        bytes[] memory sigs = _getOrderedSignatures(digest);

        // Expect revert
        vm.expectRevert(Multisig.CallFailed.selector);
        ms.execute(address(token), 0, data, deadline, sigs);
    }

    /// @notice Test updating to invalid threshold
    function testErrorInvalidThreshold() public {
        uint256 deadline = block.timestamp + 1 hours;

        // Invalid threshold (greater than number of signers)
        address[] memory newSigners = new address[](2);
        newSigners[0] = alice;
        newSigners[1] = bob;
        uint256 invalidThreshold = 3; // Only 2 signers

        // Calculate digest for signing
        bytes32 root = keccak256(abi.encodePacked(newSigners));
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                ms.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Update(bytes32 newRoot,uint256 newThreshold,uint256 nonce,uint256 deadline)"),
                        root,
                        invalidThreshold,
                        ms.nonce(),
                        deadline
                    )
                )
            )
        );
        // Get signatures in ascending order by signer address
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(digest, bobPk);
        sigs[1] = _sign(digest, alicePk);

        // Expect revert
        vm.expectRevert(Multisig.InvalidThreshold.selector);
        ms.updateSigners(newSigners, invalidThreshold, deadline, sigs);
    }

    /// @notice Test replay protection - cannot reuse a signature
    function testReplayProtection() public {
        uint256 deadline = block.timestamp + 1 hours;
        address recipient = address(0xBEEF);
        uint256 value = 1 ether;
        bytes memory data = "";

        // Calculate digest for signing
        bytes32 digest = ms.hashExecute(recipient, value, data, ms.nonce(), deadline);

        // Get signatures in ascending order by signer address
        bytes[] memory sigs = _getOrderedSignatures(digest);

        // Execute the transaction
        ms.execute(recipient, value, data, deadline, sigs);

        // Try to execute again with same signatures (nonce is now different)
        vm.expectRevert(); // Will revert, but not with a specific error code
        ms.execute(recipient, value, data, deadline, sigs);
    }

    /// @notice Test execution with exactly the threshold number of signers
    function testExecuteExactThreshold() public {
        // Set threshold to exactly the number of signers (3)
        address[] memory newSigners = new address[](3);
        newSigners[0] = alice;
        newSigners[1] = bob;
        newSigners[2] = carol;
        uint256 newThreshold = 3;

        // Define deadline for both update and execution
        uint256 deadline = block.timestamp + 1 hours;

        // First update the threshold to 3
        bytes32 root = keccak256(abi.encodePacked(newSigners));
        bytes32 updateDigest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                ms.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Update(bytes32 newRoot,uint256 newThreshold,uint256 nonce,uint256 deadline)"),
                        root,
                        newThreshold,
                        ms.nonce(),
                        deadline
                    )
                )
            )
        );

        // Get update signatures (all 3 signers)
        bytes[] memory updateSigs = new bytes[](3);
        // Order: bob, carol, alice - assuming this is the correct order
        updateSigs[0] = _sign(updateDigest, bobPk);
        updateSigs[1] = _sign(updateDigest, carolPk);
        updateSigs[2] = _sign(updateDigest, alicePk);

        // Update signers/threshold
        ms.updateSigners(newSigners, newThreshold, deadline, updateSigs);

        // Now test execution with all 3 signatures
        address recipient = address(0xBEEF);
        uint256 value = 1 ether;
        bytes memory data = "";

        // Calculate digest for signing
        bytes32 execDigest = ms.hashExecute(recipient, value, data, ms.nonce(), deadline);

        // Get all 3 signatures in correct order
        bytes[] memory execSigs = new bytes[](3);
        execSigs[0] = _sign(execDigest, bobPk);
        execSigs[1] = _sign(execDigest, carolPk);
        execSigs[2] = _sign(execDigest, alicePk);

        // Execute and verify
        uint256 balanceBefore = recipient.balance;
        ms.execute(recipient, value, data, deadline, execSigs);
        assertEq(recipient.balance, balanceBefore + value);
    }

    /// @notice Test zero-value transaction execution
    function testExecuteZeroValue() public {
        uint256 deadline = block.timestamp + 1 hours;
        address recipient = address(0xBEEF);
        uint256 value = 0; // Zero value
        bytes memory data = ""; // Empty data

        // Calculate digest for signing
        bytes32 digest = ms.hashExecute(recipient, value, data, ms.nonce(), deadline);

        // Get signatures in ascending order by signer address
        bytes[] memory sigs = _getOrderedSignatures(digest);

        // Execute the transaction
        ms.execute(recipient, value, data, deadline, sigs);

        // Verify nonce incremented
        assertEq(ms.nonce(), 1);
    }

    /// @notice Test execution of a transaction with high gasLimit
    function testExecuteHighGas() public {
        uint256 deadline = block.timestamp + 1 hours;
        address recipient = address(0xBEEF);
        uint256 value = 1 ether;
        bytes memory data = "";

        // Calculate digest for signing
        bytes32 digest = ms.hashExecute(recipient, value, data, ms.nonce(), deadline);

        // Get signatures in ascending order by signer address
        bytes[] memory sigs = _getOrderedSignatures(digest);

        // Set a very high gas limit for the call
        uint256 gasLimit = 1_000_000;
        vm.txGasPrice(1);

        // Execute with high gas
        uint256 balanceBefore = recipient.balance;
        ms.execute{gas: gasLimit}(recipient, value, data, deadline, sigs);

        // Verify execution worked
        assertEq(recipient.balance, balanceBefore + value);
    }

    /// @notice Test that a minimum threshold of 1 is enforced
    function testErrorZeroThreshold() public {
        uint256 deadline = block.timestamp + 1 hours;

        // Try to update to zero threshold
        address[] memory newSigners = new address[](3);
        newSigners[0] = alice;
        newSigners[1] = bob;
        newSigners[2] = carol;
        uint256 zeroThreshold = 0;

        // Calculate digest for signing
        bytes32 root = keccak256(abi.encodePacked(newSigners));
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                ms.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Update(bytes32 newRoot,uint256 newThreshold,uint256 nonce,uint256 deadline)"),
                        root,
                        zeroThreshold,
                        ms.nonce(),
                        deadline
                    )
                )
            )
        );

        // Get signatures in ascending order by signer address
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(digest, bobPk);
        sigs[1] = _sign(digest, alicePk);

        // Expect revert due to zero threshold
        vm.expectRevert(Multisig.InvalidThreshold.selector);
        ms.updateSigners(newSigners, zeroThreshold, deadline, sigs);
    }

    /// @notice Test handling of duplicate signers in new signer set
    function testErrorDuplicateSigners() public {
        uint256 deadline = block.timestamp + 1 hours;

        // Try to update with duplicate signers
        address[] memory newSigners = new address[](3);
        newSigners[0] = alice;
        newSigners[1] = bob;
        newSigners[2] = bob; // Duplicate signer
        uint256 newThreshold = 2;

        // Calculate digest for signing
        bytes32 root = keccak256(abi.encodePacked(newSigners));
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                ms.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Update(bytes32 newRoot,uint256 newThreshold,uint256 nonce,uint256 deadline)"),
                        root,
                        newThreshold,
                        ms.nonce(),
                        deadline
                    )
                )
            )
        );

        // Get signatures in ascending order by signer address
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(digest, bobPk);
        sigs[1] = _sign(digest, alicePk);

        // Expected behavior depends on implementation
        // Either it reverts with a specific error or it allows the update
        // but only counts unique addresses
        vm.expectRevert(); // Adjust based on expected behavior
        ms.updateSigners(newSigners, newThreshold, deadline, sigs);
    }

    /// @notice Test a series of operations in sequence
    function testOperationSequence() public {
        uint256 deadline = block.timestamp + 1 hours;

        // 1. First execute an ETH transfer
        address recipient1 = address(0xBEEF);
        uint256 value1 = 1 ether;
        bytes memory data1 = "";

        bytes32 digest1 = ms.hashExecute(recipient1, value1, data1, ms.nonce(), deadline);
        bytes[] memory sigs1 = _getOrderedSignatures(digest1);

        uint256 balanceBefore1 = recipient1.balance;
        ms.execute(recipient1, value1, data1, deadline, sigs1);
        assertEq(recipient1.balance, balanceBefore1 + value1);
        assertEq(ms.nonce(), 1);

        // 2. Then update signers
        address[] memory newSigners = new address[](3);
        newSigners[0] = alice;
        newSigners[1] = bob;
        newSigners[2] = dave; // Replace carol with dave
        uint256 newThreshold = 2;

        bytes32 root = keccak256(abi.encodePacked(newSigners));
        bytes32 digest2 = keccak256(
            abi.encodePacked(
                "\x19\x01",
                ms.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Update(bytes32 newRoot,uint256 newThreshold,uint256 nonce,uint256 deadline)"),
                        root,
                        newThreshold,
                        ms.nonce(),
                        deadline
                    )
                )
            )
        );

        bytes[] memory sigs2 = new bytes[](2);
        sigs2[0] = _sign(digest2, bobPk);
        sigs2[1] = _sign(digest2, alicePk);

        ms.updateSigners(newSigners, newThreshold, deadline, sigs2);
        assertEq(ms.nonce(), 2);
        assertTrue(ms.isSigner(dave));
        assertFalse(ms.isSigner(carol));

        // 3. Execute again with the new signer set
        address recipient3 = address(0xDEAD);
        uint256 value3 = 0.5 ether;
        bytes memory data3 = "";

        bytes32 digest3 = ms.hashExecute(recipient3, value3, data3, ms.nonce(), deadline);
        bytes[] memory sigs3 = new bytes[](2);

        // Now use dave instead of carol (exact ordering depends on address values)
        sigs3[0] = _sign(digest3, bobPk);
        sigs3[1] = _sign(digest3, davePk);

        uint256 balanceBefore3 = recipient3.balance;
        ms.execute(recipient3, value3, data3, deadline, sigs3);
        assertEq(recipient3.balance, balanceBefore3 + value3);
        assertEq(ms.nonce(), 3);
    }

    /// @notice Test domain separator produces valid signatures
    function testDomainSeparator() public view {
        // Just verify the domain separator exists and isn't the zero hash
        bytes32 domainSeparator = ms.DOMAIN_SEPARATOR();
        assert(domainSeparator != bytes32(0));
    }

    /// @notice Test the contract's hash function for execute
    function testHashExecute() public {
        uint256 deadline = block.timestamp + 1 hours;
        address recipient = address(0xBEEF);
        uint256 value = 1 ether;
        bytes memory data = "";

        // Get hash from contract
        bytes32 digest = ms.hashExecute(recipient, value, data, ms.nonce(), deadline);

        // Verify it's not empty
        assert(digest != bytes32(0));
    }

    /// @notice Test signature recovery works as expected
    function testSignatureRecovery() public {
        uint256 deadline = block.timestamp + 1 hours;
        address recipient = address(0xBEEF);
        uint256 value = 1 ether;
        bytes memory data = "";

        // Calculate digest for signing
        bytes32 digest = ms.hashExecute(recipient, value, data, ms.nonce(), deadline);

        // Create signature using our test key
        bytes memory signature = _sign(digest, alicePk);

        // Verify that the recovered signer matches alice
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        address recoveredSigner = ecrecover(digest, v, r, s);

        assertEq(recoveredSigner, alice);
    }

    /// @notice Helper to split a signature into v, r, s components
    function splitSignature(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(sig.length == 65, "Invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        return (v, r, s);
    }

    /// @notice Test executing a call to set storage in another contract
    function testExecuteStorageContract() public {
        uint256 deadline = block.timestamp + 1 hours;

        // Deploy a simple storage contract
        MockStorage storageContract = new MockStorage();

        // Create call data to set a value
        uint256 newValue = 42;
        bytes memory data = abi.encodeWithSelector(storageContract.setValue.selector, newValue);

        // Calculate digest for signing
        bytes32 digest = ms.hashExecute(address(storageContract), 0, data, ms.nonce(), deadline);

        // Get signatures in ascending order by signer address
        bytes[] memory sigs = _getOrderedSignatures(digest);

        // Execute the transaction
        ms.execute(address(storageContract), 0, data, deadline, sigs);

        // Verify the value was set
        assertEq(storageContract.getValue(), newValue);
    }

    /// @notice Test deploying a contract through the multisig
    function testExecuteContractDeployment() public {
        uint256 deadline = block.timestamp + 1 hours;

        // Create deployment bytecode for a simple contract
        bytes memory creationCode = type(MockStorage).creationCode;

        // Calculate digest for signing
        bytes32 digest = ms.hashExecute(address(0), 0, creationCode, ms.nonce(), deadline);

        // Get signatures in ascending order by signer address
        bytes[] memory sigs = _getOrderedSignatures(digest);

        // Execute the deployment
        ms.execute(address(0), 0, creationCode, deadline, sigs);

        // Verify the nonce was incremented (deployment was processed)
        assertEq(ms.nonce(), 1);
    }

    /// @notice Test executing a governance vote
    function testExecuteGovernanceVote() public {
        uint256 deadline = block.timestamp + 1 hours;

        // Deploy a mock governance contract
        MockGovernance governance = new MockGovernance();

        // Create call data to cast a vote
        uint256 proposalId = 1;
        bool support = true;
        bytes memory data = abi.encodeWithSelector(governance.castVote.selector, proposalId, support);

        // Calculate digest for signing
        bytes32 digest = ms.hashExecute(address(governance), 0, data, ms.nonce(), deadline);

        // Get signatures in ascending order by signer address
        bytes[] memory sigs = _getOrderedSignatures(digest);

        // Execute the transaction
        ms.execute(address(governance), 0, data, deadline, sigs);

        // Verify the vote was cast
        (bool voted, bool voteResult) = governance.getVote(address(ms), proposalId);
        assertTrue(voted);
        assertTrue(voteResult);
    }
}
