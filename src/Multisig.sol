// SPDX‑License‑Identifier: MIT
import {ECDSA} from "@openzeppelin/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/utils/cryptography/EIP712.sol";

import {IMultisig} from "./interfaces/IMultisig.sol";

/// @title Multisig
/// @notice Gas‑lean k‑of‑n EIP‑712 Multisig
/// @dev Implements a multisignature wallet using EIP-712 for typed data signing
contract Multisig is EIP712, IMultisig {
    using ECDSA for bytes32;

    /* --------------------------------------------------------------------- */
    /*                               Errors                                  */
    /* --------------------------------------------------------------------- */
    /// @notice Thrown when threshold is invalid (0 or greater than signer count)
    error InvalidThreshold();
    /// @notice Thrown when attempting to add the same signer twice
    error DuplicateSigner();
    /// @notice Thrown when a signature is from an address that isn't a signer
    error UnknownSigner();
    /// @notice Thrown when signatures aren't provided in ascending order by signer address
    error BadSignatureOrder();
    /// @notice Thrown when there aren't enough valid signatures to meet the threshold
    error NotEnoughSigners();
    /// @notice Thrown when a call to the target contract fails
    error CallFailed();
    /// @notice Thrown when the transaction deadline has passed
    error DeadlineExpired();

    /* --------------------------------------------------------------------- */
    /*                           Storage layout                              */
    /* --------------------------------------------------------------------- */
    /// @notice List of authorized signers
    address[] public signers; // slot‑0
    /// @notice Mapping to quickly check if an address is an authorized signer
    mapping(address => bool) public isSigner; // slot‑1+

    /// @notice Transaction sequence number to prevent replay attacks
    uint128 public nonce; // slot‑2  (lower 128 bits)
    /// @notice Number of signers required to authorize a transaction
    uint128 public threshold; // slot‑2  (upper 128 bits)

    /* --------------------------------------------------------------------- */
    /*                                Events                                 */
    /* --------------------------------------------------------------------- */
    /// @notice Emitted when a transaction is successfully executed
    /// @param target The address that was called
    /// @param value The amount of ETH sent with the call
    /// @param data The calldata passed to the target address
    /// @param nonce The sequence number of the transaction
    /// @param deadline The timestamp after which the transaction would have been invalid
    event Executed(address indexed target, uint256 value, bytes data, uint256 nonce, uint256 deadline);

    /// @notice Emitted when the signer set is updated
    /// @param newSigners The new list of authorized signers
    /// @param newThreshold The new signature threshold
    event SignersUpdated(address[] newSigners, uint256 newThreshold);

    /* --------------------------------------------------------------------- */
    /*                            Constructor                                */
    /* --------------------------------------------------------------------- */
    /// @notice Creates a new Multisig contract with initial signers and threshold
    /// @param _signers Array of initial signer addresses
    /// @param _threshold Minimum number of signatures required (must be ≤ _signers.length)
    /// @dev Initializes EIP-712 with the name "Multisig" and version "2"
    constructor(
        address[] memory _signers,
        uint256 _threshold
    )
        EIP712("Multisig", "2") // OZ EIP‑712 helper
    {
        _setSigners(_signers, _threshold);
    }

    /* --------------------------------------------------------------------- */
    /*                             EIP‑712 Types                             */
    /* --------------------------------------------------------------------- */
    /// @dev Hash of the execute operation type string for EIP-712
    bytes32 private constant EXECUTE_TYPEHASH =
        keccak256("Execute(address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)");
    /// @dev Hash of the update operation type string for EIP-712
    bytes32 private constant UPDATE_TYPEHASH =
        keccak256("Update(bytes32 newRoot,uint256 newThreshold,uint256 nonce,uint256 deadline)");

    /* --------------------------------------------------------------------- */
    /*                           User‑facing API                             */
    /* --------------------------------------------------------------------- */
    /// @notice Execute a transaction if authorized by enough signers
    /// @param target Address to call
    /// @param value Amount of ETH to send with the call
    /// @param data Calldata to pass to the target
    /// @param deadline Timestamp after which the signatures are invalid
    /// @param sigs Array of signatures from authorized signers, sorted by signer address
    /// @return ret The return data from the called function
    /// @dev Signatures must be sorted by signer address to prevent signature reuse
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 deadline,
        bytes[] calldata sigs
    ) external override returns (bytes memory ret) {
        if (block.timestamp > deadline) revert DeadlineExpired();

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(EXECUTE_TYPEHASH, target, value, keccak256(data), nonce, deadline))
        );
        _verifySignatures(digest, sigs);

        ++nonce;
        (bool ok, bytes memory result) = target.call{value: value}(data);
        if (!ok) revert CallFailed();

        emit Executed(target, value, data, nonce - 1, deadline);
        return result;
    }

    /// @notice Update the set of signers and the threshold
    /// @param newSigners New array of signer addresses
    /// @param newThreshold New minimum number of signatures required
    /// @param deadline Timestamp after which the signatures are invalid
    /// @param sigs Array of signatures from current authorized signers, sorted by signer address
    /// @dev Requires signatures from enough current signers to meet the current threshold
    function updateSigners(
        address[] calldata newSigners,
        uint256 newThreshold,
        uint256 deadline,
        bytes[] calldata sigs
    ) external override {
        if (block.timestamp > deadline) revert DeadlineExpired();

        bytes32 root = keccak256(abi.encodePacked(newSigners));
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(UPDATE_TYPEHASH, root, newThreshold, nonce, deadline)));
        _verifySignatures(digest, sigs);

        ++nonce;
        _setSigners(newSigners, newThreshold);
        emit SignersUpdated(newSigners, newThreshold);
    }

    /* --------------------------------------------------------------------- */
    /*                        Internal helper logic                          */
    /* --------------------------------------------------------------------- */
    /// @dev Sets a new list of signers and threshold
    /// @param _s Array of signer addresses
    /// @param _t New threshold value
    /// @dev Clears all previous signers before setting new ones
    function _setSigners(address[] memory _s, uint256 _t) private {
        if (_s.length == 0 || _t == 0 || _t > _s.length) revert InvalidThreshold();

        // clear old set
        uint256 len = signers.length;
        for (uint256 i; i < len; ) {
            isSigner[signers[i]] = false;
            unchecked {
                ++i;
            }
        }
        delete signers;

        // load new
        for (uint256 i; i < _s.length; ) {
            address a = _s[i];
            if (a == address(0) || isSigner[a]) revert DuplicateSigner();

            isSigner[a] = true;
            signers.push(a);

            unchecked {
                ++i;
            }
        }
        threshold = uint128(_t);
    }

    /// @dev Verifies signatures against a digest
    /// @param digest The hash to verify signatures against
    /// @param sigs   Array of signatures to verify
    /// @dev Enforces signatures are from valid signers and in ascending order by signer address
    function _verifySignatures(bytes32 digest, bytes[] calldata sigs) private view {
        if (sigs.length < threshold) revert NotEnoughSigners();

        address prev;
        for (uint256 i; i < sigs.length; ) {
            address signer = digest.recover(sigs[i]);

            if (signer <= prev) revert BadSignatureOrder();
            if (!isSigner[signer]) revert UnknownSigner();

            prev = signer;
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Allows the contract to receive ETH
    /// @dev Required to be able to receive ETH transfers
    receive() external payable {}

    /**
     * @notice Returns the domain separator for EIP-712 signing
     * @return The domain separator
     * @dev Used by external tools for signature verification
     */
    function DOMAIN_SEPARATOR() external view override returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @notice Helper function to hash execution parameters for external verification
     * @param target Address to call
     * @param value ETH value to send
     * @param data Call data
     * @param nonceVal Nonce value to use
     * @param deadline Timestamp after which the signature is invalid
     * @return Typed data hash ready for signing
     * @dev Useful for generating the message to sign in external tools
     */
    function hashExecute(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 nonceVal,
        uint256 deadline
    ) external view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(abi.encode(EXECUTE_TYPEHASH, target, value, keccak256(data), nonceVal, deadline))
            );
    }
}
