# ---------------------------------------------------------------------------- #
#                             Multisig Wallet Makefile                         #
# ---------------------------------------------------------------------------- #

GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m

# Load environment variables from .env file
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# ---------------------------------------------------------------------------- #
#                                    Targets                                   #
# ---------------------------------------------------------------------------- #

.PHONY: all fmt build test clean deploy propose-execute propose-update sign execute help local-flow

## all: Build + Test
all: build test

## help: Display this help message
help:
	@echo "$(YELLOW)Multisig Wallet Makefile$(NC)"
	@echo "$(YELLOW)--------------------$(NC)"
	@echo "Usage: make [target]"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@grep -E '^## [a-zA-Z_-]+:' Makefile | sed 's/## //' | sort

## fmt: Format code (optional)
fmt:
	@echo "$(YELLOW)✍  Formatting code...$(NC)"
	forge fmt
	@echo "\n$(GREEN)✅ Formatting code completed successfully!$(NC)\n"

## build: Builds the project using Foundry
build:
	@echo "\n$(YELLOW)🔨 Building the project...$(NC)\n"
	forge build
	@echo "\n$(GREEN)✅ Build completed successfully!$(NC)\n"

## build: Builds the project using Foundry
build-sizes:
	@echo "\n$(YELLOW)🔨 Building the project...$(NC)\n"
	forge build --sizes
	@echo "\n$(GREEN)✅ Build completed successfully!$(NC)\n"

## clean: Clean build artifacts
clean:
	@echo "$(YELLOW)🧹 Cleaning artifacts...$(NC)"
	forge clean
	@echo "\n$(GREEN)✅ Cleaning completed successfully!$(NC)\n"

## test: Run all tests
test: build
	@echo "$(YELLOW)🧪 Running tests...$(NC)"
	forge test -vvv
	@echo "\n$(GREEN)✅ Tests completed successfully!$(NC)\n"

## deploy: Deploy multisig wallet
deploy:
	@echo "$(YELLOW)🚀 Deploying Multisig wallet...$(NC)"
	@if [ -z "$(RPC_URL)" ]; then \
		echo "$(RED)❌ RPC_URL is not set. Please set it in your .env file.$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(DEPLOYER_PK)" ]; then \
		echo "$(RED)❌ DEPLOYER_PK is not set. Please set it in your .env file.$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(A_PK)" ] || [ -z "$(B_PK)" ] || [ -z "$(C_PK)" ]; then \
		echo "$(RED)❌ Signer private keys (A_PK, B_PK, C_PK) are required. Please set them in your .env file.$(NC)"; \
		exit 1; \
	fi
	forge script script/Deploy.s.sol --rpc-url $(RPC_URL) --broadcast
	@echo "\n$(GREEN)✅ Deployment completed!$(NC)\n"

## propose-execute: Generate transaction digest for execution
propose-execute:
	@echo "$(YELLOW)📝 Generating execute transaction digest...$(NC)"
	@if [ -z "$(RPC_URL)" ]; then \
		echo "$(RED)❌ RPC_URL is not set. Please set it in your .env file.$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(MSIG)" ]; then \
		echo "$(RED)❌ MSIG address is not set. Please set it in your .env file.$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(TARGET)" ]; then \
		echo "$(RED)❌ TARGET is required. Example: make propose-execute TARGET=0xaddress VALUE=1000000000000000000 DATA=0x$(NC)"; \
		exit 1; \
	fi
	TX_TYPE="execute" TARGET=$(TARGET) VALUE=$(VALUE) DATA=$(DATA) forge script script/Propose.s.sol --rpc-url $(RPC_URL)
	@echo "\n$(GREEN)✅ Transaction proposal generated!$(NC)\n"

## propose-update: Generate transaction digest for updating signers
propose-update:
	@echo "$(YELLOW)📝 Generating updateSigners transaction digest...$(NC)"
	@if [ -z "$(RPC_URL)" ]; then \
		echo "$(RED)❌ RPC_URL is not set. Please set it in your .env file.$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(MSIG)" ]; then \
		echo "$(RED)❌ MSIG address is not set. Please set it in your .env file.$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(NEW_SIGNERS)" ] || [ -z "$(NEW_THRESHOLD)" ]; then \
		echo "$(RED)❌ NEW_SIGNERS and NEW_THRESHOLD are required. Example: make propose-update NEW_SIGNERS='[0x123...,0x456...]' NEW_THRESHOLD=2$(NC)"; \
		exit 1; \
	fi
	TX_TYPE="update" NEW_SIGNERS=$(NEW_SIGNERS) NEW_THRESHOLD=$(NEW_THRESHOLD) forge script script/Propose.s.sol --rpc-url $(RPC_URL)
	@echo "\n$(GREEN)✅ Update proposal generated!$(NC)\n"

## sign: Sign a transaction digest
sign:
	@echo "$(YELLOW)✍️  Signing transaction digest...$(NC)"
	@if [ -z "$(DIGEST)" ]; then \
		echo "$(RED)❌ DIGEST is required. Example: make sign DIGEST=0x123... SIGNER_PK=0xprivatekey$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(SIGNER_PK)" ]; then \
		echo "$(RED)❌ SIGNER_PK is required. Example: make sign DIGEST=0x123... SIGNER_PK=0xprivatekey$(NC)"; \
		exit 1; \
	fi
	DIGEST=$(DIGEST) SIGNER_PK=$(SIGNER_PK) forge script script/Sign.s.sol
	@echo "\n$(GREEN)✅ Transaction signed!$(NC)\n"

## execute-tx: Execute a transaction with collected signatures
execute-tx:
	@echo "$(YELLOW)🚀 Executing transaction...$(NC)"
	@if [ -z "$(RPC_URL)" ]; then \
		echo "$(RED)❌ RPC_URL is not set. Please set it in your .env file.$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(MSIG)" ]; then \
		echo "$(RED)❌ MSIG address is not set. Please set it in your .env file.$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(TX_TYPE)" ]; then \
		echo "$(RED)❌ TX_TYPE is required (execute or update). Example: make execute-tx TX_TYPE=execute ...$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(DEADLINE)" ]; then \
		echo "$(RED)❌ DEADLINE is required. Use a unix timestamp.$(NC)"; \
		exit 1; \
	fi
	@if [ -z "$(SIGNATURES)" ]; then \
		echo "$(RED)❌ SIGNATURES is required. Format as a JSON array of hex strings.$(NC)"; \
		exit 1; \
	fi
	@if [ "$(TX_TYPE)" = "execute" ] && ([ -z "$(TARGET)" ] || [ -z "$(VALUE)" ] || [ -z "$(DATA)" ]); then \
		echo "$(RED)❌ For execute: TARGET, VALUE, and DATA are required.$(NC)"; \
		exit 1; \
	fi
	@if [ "$(TX_TYPE)" = "update" ] && ([ -z "$(NEW_SIGNERS)" ] || [ -z "$(NEW_THRESHOLD)" ]); then \
		echo "$(RED)❌ For update: NEW_SIGNERS and NEW_THRESHOLD are required.$(NC)"; \
		exit 1; \
	fi
	@if [ "$(TX_TYPE)" = "execute" ]; then \
		TX_TYPE=$(TX_TYPE) TARGET=$(TARGET) VALUE=$(VALUE) DATA=$(DATA) DEADLINE=$(DEADLINE) SIGNATURES=$(SIGNATURES) \
		forge script script/Execute.s.sol --rpc-url $(RPC_URL) --broadcast; \
	else \
		TX_TYPE=$(TX_TYPE) NEW_SIGNERS=$(NEW_SIGNERS) NEW_THRESHOLD=$(NEW_THRESHOLD) DEADLINE=$(DEADLINE) SIGNATURES=$(SIGNATURES) \
		forge script script/Execute.s.sol --rpc-url $(RPC_URL) --broadcast; \
	fi
	@echo "\n$(GREEN)✅ Transaction executed!$(NC)\n"

## local-flow: Run the complete multisig workflow on a local blockchain
local-flow:
	@echo "\n$(YELLOW)🚀 Running complete multisig workflow on local blockchain...$(NC)\n"
	
	# Step 1: Start a local Anvil blockchain instance in the background
	@echo "$(YELLOW)1️⃣ Starting a local Anvil chain...$(NC)"
	@anvil --silent > /dev/null 2>&1 & echo $$! > .anvil.pid
	@sleep 2
	
	# Step 2: Create a temporary .env.local file with test private keys
	@echo "$(YELLOW)2️⃣ Setting up test private keys...$(NC)"
	@echo "DEPLOYER_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" > .env.local
	@echo "A_PK=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" >> .env.local
	@echo "B_PK=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" >> .env.local
	@echo "C_PK=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" >> .env.local
	@echo "RPC_URL=http://localhost:8545" >> .env.local
	
	# Step 3: Deploy the multisig contract with 3 signers and threshold=2
	@echo "$(YELLOW)3️⃣ Deploying multisig...$(NC)"
	@DEPLOYER_PK=$$(grep DEPLOYER_PK .env.local | cut -d= -f2) \
	 A_PK=$$(grep A_PK .env.local | cut -d= -f2) \
	 B_PK=$$(grep B_PK .env.local | cut -d= -f2) \
	 C_PK=$$(grep C_PK .env.local | cut -d= -f2) \
	 RPC_URL=$$(grep RPC_URL .env.local | cut -d= -f2) \
	 forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast > deploy_output.txt
	
	# Extract the deployed contract address and save it to .env.local
	@echo "Contract deployed. Extracting address..."
	@MSIG_ADDR=$$(grep -oE '0x[0-9a-fA-F]{40}' deploy_output.txt | head -n 1) && \
	 echo "MSIG=$$MSIG_ADDR" >> .env.local && \
	 echo "Multisig deployed to: $$MSIG_ADDR"
	
	# Step 4: Propose a transaction (1 ETH transfer to a test address)
	@echo "$(YELLOW)4️⃣ Proposing a test transaction (1 ETH transfer)...$(NC)"
	@MSIG=$$(grep MSIG .env.local | cut -d= -f2) \
	 RPC_URL=http://localhost:8545 \
	 TX_TYPE="execute" TARGET=0x70997970C51812dc3A010C7d01b50e0d17dc79C8 VALUE=1000000000000000000 DATA=0x \
	 forge script script/Propose.s.sol --rpc-url http://localhost:8545 > propose_output.txt
	
	# Extract the transaction digest and deadline from the proposal output
	@echo "Transaction proposed. Extracting digest & deadline..."
	@DIGEST=$$(grep -A 1 "Generated execute transaction digest:" propose_output.txt | tail -n 1 | tr -d '[:space:]') && \
	 echo "DIGEST=$$DIGEST" >> .env.local && \
	 DEADLINE=$$(grep "Deadline:" propose_output.txt | awk '{print $$2}') && \
	 echo "DEADLINE=$$DEADLINE" >> .env.local && \
	 echo "Transaction digest: $$DIGEST" && \
	 echo "Deadline:          $$DEADLINE"
	
	# Step 5: Sign the transaction with the first signer (using private key A_PK)
	@echo "$(YELLOW)5️⃣ Signing with first signer...$(NC)"
	@DIGEST=$$(grep DIGEST .env.local | cut -d= -f2) \
	 SIGNER_PK=$$(grep A_PK .env.local | cut -d= -f2) \
	 forge script script/Sign.s.sol > sig_a_output.txt
	
	# Extract and save the first signature
	@echo "First signature collected."
	@SIG_A=$$(grep -A 3 "Signature (hex):" sig_a_output.txt | tail -n 1 | tr -d '[:space:]') && \
	 echo "SIG_A=$$SIG_A" >> .env.local && \
	 echo "Signature A: $$SIG_A"
	
	# Step 6: Sign the transaction with the second signer (using private key B_PK)
	@echo "$(YELLOW)6️⃣ Signing with second signer...$(NC)"
	@DIGEST=$$(grep DIGEST .env.local | cut -d= -f2) \
	 SIGNER_PK=$$(grep B_PK .env.local | cut -d= -f2) \
	 forge script script/Sign.s.sol > sig_b_output.txt
	
	# Extract and save the second signature
	@echo "Second signature collected."
	@SIG_B=$$(grep -A 3 "Signature (hex):" sig_b_output.txt | tail -n 1 | tr -d '[:space:]') && \
	 echo "SIG_B=$$SIG_B" >> .env.local && \
	 echo "Signature B: $$SIG_B"
	
	# Step 7: Execute the transaction with both signatures
	# This sends 1 ETH from the multisig to address 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
	@echo "$(YELLOW)7️⃣ Executing the transaction...$(NC)"
	@DEADLINE=$$(grep DEADLINE .env.local | cut -d= -f2) && \
	 echo "Using deadline: $$DEADLINE" && \
	 MSIG=$$(grep MSIG .env.local | cut -d= -f2) \
	 RPC_URL=http://localhost:8545 \
	 DEPLOYER_PK=$$(grep DEPLOYER_PK .env.local | cut -d= -f2) \
	 SIG_A=$$(grep SIG_A .env.local | cut -d= -f2) \
	 SIG_B=$$(grep SIG_B .env.local | cut -d= -f2) \
	 TX_TYPE="execute" \
	 TARGET=0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
	 VALUE=1000000000000000000 \
	 DATA=0x \
	 DEADLINE=$$DEADLINE \
	 SIGNATURES="$$(grep SIG_A .env.local | cut -d= -f2),$$(grep SIG_B .env.local | cut -d= -f2)" \
	 forge script script/Execute.s.sol --rpc-url http://localhost:8545 --broadcast
	
	# Step 8: Clean up - kill the Anvil process and remove temporary files
	@echo "$(YELLOW)8️⃣ Cleaning up...$(NC)"
	@if [ -f .anvil.pid ]; then \
	    PID=$$(cat .anvil.pid);       \
	    kill $$PID 2>/dev/null || true; \
	    rm .anvil.pid;               \
	fi
	@rm -f .env.local sig_a_output.txt sig_b_output.txt deploy_output.txt propose_output.txt
	
	@echo "\n$(GREEN)✅ Multisig workflow completed successfully!$(NC)\n" 