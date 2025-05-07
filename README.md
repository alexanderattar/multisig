# Multisig Wallet

A gas-efficient, k-of-n signature EIP-712 multisignature wallet implementation in Solidity with Foundry.

## Features

- **K-of-N Threshold Signatures**: Requires a minimum number (k) of signatures from authorized signers (n) to execute transactions
- **EIP-712 Signing**: Secure typed data signing with domain separation
- **Arbitrary Transaction Execution**: Execute any call to any contract with ETH value
- **Signer Management**: Authorized signers can update the signer set and threshold
- **Gas Efficient**: Optimized implementation using modern Solidity patterns
- **Well-Documented**: Thoroughly commented codebase with NatSpec documentation

## Architecture

The system consists of:

1. **Multisig.sol**: Core multisignature wallet contract
2. **IMultisig.sol**: Interface for the multisig contract
3. **Deployment Scripts**: For deploying the multisig wallet
4. **Interaction Scripts**: For generating proposals, signing, and executing transactions
5. **Makefile**: Provides commands for building, testing, and interacting with the multisig

## Setup

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- GNU Make (comes pre-installed on most Linux/macOS systems, for Windows use [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) or [Git Bash](https://gitforwindows.org/))
- Bash shell environment

### Installation

1. Clone the repository:

```bash
git clone https://github.com/alexanderattar/multisig
cd multisig
```

2. Install dependencies:

```bash
forge install
```

3. Set up your environment variables by creating a `.env` file:

```
RPC_URL=<your-rpc-url>
DEPLOYER_PK=<private-key-for-deployment>
A_PK=<private-key-for-signer-a>
B_PK=<private-key-for-signer-b>
C_PK=<private-key-for-signer-c>
MSIG=<multisig-address> # Set after deployment
```

## Usage

Run `make help` to see all available commands.

### 1. Deploying the Multisig

Deploy the multisig with initial signers:

```bash
make deploy
```

This uses the private keys `A_PK`, `B_PK`, and `C_PK` from your .env file to set up the initial signers, with a threshold of 2 signatures.

### 2. Proposing a Transaction

#### To propose an ETH transfer:

```bash
make propose-execute TARGET=0xRecipientAddress VALUE=1000000000000000000 DATA=0x
```

This creates a transaction that will send 1 ETH to the recipient address.

#### To propose a contract call:

```bash
make propose-execute TARGET=0xContractAddress VALUE=0 DATA=0xa9059cbb000000000000000000000000recipient000000000000000000000000000000000000000000000000000000000000000000000000000000000000de0b6b3a7640000
```

This creates a transaction to call a contract method (in this example, an ERC-20 transfer).

#### To propose updating the signers:

```bash
make propose-update NEW_SIGNERS='[0x123...456,0x789...abc,0xdef...123]' NEW_THRESHOLD=2
```

This proposes updating the signer set to the addresses in the JSON array with a threshold of 2.

### 3. Signing a Transaction

After proposing a transaction, signers need to add their signatures:

```bash
make sign DIGEST=0xdigest-from-propose-step SIGNER_PK=0xSIGNER_PRIVATE_KEY
```

Each signer must do this independently using their own private key.

### 4. Executing a Transaction

Once enough signatures have been collected, execute the transaction:

For a regular transaction:

```bash
make execute-tx TX_TYPE=execute TARGET=0xTargetAddress VALUE=1000000000000000000 DATA=0x DEADLINE=1718106444 SIGNATURES='["0xsig1","0xsig2"]'
```

For updating signers:

```bash
make execute-tx TX_TYPE=update NEW_SIGNERS='[0x123...456,0x789...abc,0xdef...123]' NEW_THRESHOLD=2 DEADLINE=1718106444 SIGNATURES='["0xsig1","0xsig2"]'
```

The timestamp (1718106444 in this example) is the deadline after which the signatures are no longer valid.

## Testing

Run the test suite:

```bash
make test
```

Run the formatter:

```bash
make fmt
```

## Local Workflow Demo

The project includes a complete end-to-end workflow demonstration that runs on a local Anvil chain. This is hopefully the easiest way to see the multisig in action! :)

```bash
make local-flow
```

This command:

1. Starts a local Anvil blockchain
2. Sets up test accounts with private keys
3. Deploys the multisig contract with 3 signers and a threshold of 2
4. Proposes a test transaction (1 ETH transfer)
5. Signs the transaction with two different signers
6. Executes the transaction with the collected signatures
7. Cleans up temporary files

The workflow demonstrates the complete lifecycle of a multisig transaction:

- Deployment
- Transaction proposal
- Signature collection
- Transaction execution

## Advanced Usage

### Working with Signatures

For managing signatures in a production environment:

```bash
# Store signature
echo "0x123..." > sig1.txt

# Combine signatures for execution
export SIGNATURES="$(cat sig1.txt),$(cat sig2.txt)"
make execute-tx TX_TYPE=execute TARGET=0xTarget VALUE=1000000000000000000 DATA=0x DEADLINE=1718106444 SIGNATURES="$SIGNATURES"
```

### Security Best Practices

1. **Private Key Management**: Never store private keys in plain text or in code
2. **Signature Verification**: Always verify signatures off-chain before submitting to save gas
3. **Deadline Setting**: Set reasonable deadlines to prevent replay attacks
4. **Transaction Review**: Always review the exact parameters of a transaction before signing

## Contract Details

### Multisig.sol

The core contract implementing the multisignature functionality:

- Uses EIP-712 for typed data signing
- Enforces signature order to prevent duplicates
- Handles both general execution and signer updates
- Emits events for all significant actions
- Includes helper functions for off-chain signature generation

### Security Features

1. **Replay Protection**: Uses increasing nonce values
2. **Signature Verification**: Validates signer authorization and signature order
3. **Expiration Timestamps**: All transactions have deadlines
4. **Threshold Enforcement**: Requires minimum number of valid signatures

## Future Development

### Potential Enhancements

- Support for batched transactions
- Web interface for easier signature management
- Improved event indexing for off-chain monitoring

### Extension Points

To extend the multisig with additional features:

1. Add new methods to the `IMultisig.sol` interface
2. Implement the methods in `Multisig.sol`
3. Update the scripts to support the new functionality
4. Add tests in `test/Multisig.t.sol`

## License

MIT License
