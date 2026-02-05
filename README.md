# ICT3009 — Bitcoin Transaction Verification on Ethereum (Solidity + Foundry)

This repository contains my coursework implementation for **ICT3009**, built in **Solidity** and tested using **Foundry**.

## What this implements (Tasks 1–5)
- Bitcoin utilities: double-SHA256, endianness helpers, VarInt parsing
- Bitcoin-style Merkle proof verification (double-SHA256 parent hashing)
- Bitcoin block header chain verification that stores **only block hashes** + heights (not full headers)
- ERC-20 token (initial supply = 0, mint only via transaction verification, burn supported)
- Transaction verification that proves a **P2PKH or P2PK** transaction output is included in a known block, then mints ERC-20 tokens equal to the output value (satoshis)
- Unified workflow (oracle submits headers → user submits tx proof → contract verifies & mints)

---

## Tooling
This project uses **Foundry** (`forge`, `cast`, `anvil`).

Install docs: https://book.getfoundry.sh/

---

## Project structure

### Contracts (`src/`)
- `BTCUtils.sol`  
  Bitcoin helper library: `sha256d`, `reverseBytes32`, endianness helpers, parsing helpers.

- `MerkleProofBTC.sol`  
  Verifies Bitcoin-style Merkle proofs using double-SHA256 at each parent.

- `BitcoinHeaderChain.sol`  
  Accepts 80-byte Bitcoin headers and stores only:
  - `blockHash -> height`
  - `blockHash -> merkleRoot` (needed for Task 4)

  Verifies:
  - header length = 80 bytes
  - `prevBlockHash` references a previously stored block
  - difficulty target from `bits`
  - PoW: `hash <= target`
  - minimum difficulty requirement (70 billion)

- `BtcVerifierToken.sol`  
  ERC-20 + verify-and-mint logic:
  - ERC-20: `totalSupply`, `balanceOf`, `transfer`, `approve`, `allowance`, `transferFrom`, events
  - initial supply = **0**
  - minting is **not user-callable** (triggered by verification)
  - burn + burnFrom
  - Required interface: `verifyTransaction(bytes,bytes32[],uint256,bytes32)`

### Tests (`test/`)
- `BTCUtils.t.sol` — BTC utils tests
- `MerkleProof.t.sol` — Merkle proof verifier tests
- `HeaderChain.t.sol` — header submission / chaining / PoW tests
- `BtcVerifierToken_ERC20.t.sol` — ERC-20 behavior tests
- `VerifyTransaction.t.sol` — Task 4 tx verification tests
- `Integration.t.sol` — end-to-end header → verifyTx → mint
- `UnifiedSystem.t.sol` — integrated "Task 5 style" system flow tests
- `OracleFlow.t.sol` — oracle access control flow tests

### Fixtures (`test/fixtures`)
- `sample_header.hex`
- `sample_tx.hex`
- `sample_proof.json`

### Docs (`docs/`)
- `docs/ai-prompts.md` — log of AI prompts used during development (coursework requirement)
- `docs/TASK4.md` — Task 4 write-up + required explanation about PKH vs Ethereum addresses + suggested improvements

### Scripts (`script/`)
- `Deploy.s.sol` — deployment script
- `DemoFlow.s.sol` — demonstrates a full flow (submit header, verify tx, observe mint)
- `make_integration_fixtures.py` — helper for generating fixtures

---

## Endianness conventions used

Bitcoin serialization uses little-endian in multiple places, so this repo uses explicit conventions:

- **Stored block hashes** are **canonical/explorer-style** `bytes32`:
  - `blockHashCanonical = reverseBytes32(sha256d(header))`

- The block's **Merkle root** is stored **exactly as it appears in the header field** (header byte order).

- Transaction ID used in Merkle proof verification:
  - **Legacy txid** = `sha256d(fullTxBytes)`
  - **SegWit txid** = `sha256d(strippedSerializationWithoutWitness)`  
    (marker/flag and witness are excluded from txid)

Merkle verification expects all hashes passed in the same byte order that the hashing uses.

---

## Build + test

### Build
```sh
forge build
```

### Test
```sh
forge test -vvv
```

---

## Deploy + interact

### Option A — Local (Anvil)

**Terminal 1:**
```sh
anvil
```

**Terminal 2 (set env vars):**
```sh
export RPC_URL="http://127.0.0.1:8545"

# anvil account (0) private key (shown when you run anvil)
export PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Contract constructor inputs
export CHECKPOINT_HASH="0x00000000000000000001919a930d370882a7712e0fb8cfb69bd4a9cc58077311"
export CHECKPOINT_HEIGHT="800000"
export TARGET_PKH="0x91ff9f2eed45fe06fab4875df1bd40b1d77d1bfc"

# Token metadata (optional)
export TOKEN_NAME="BTC Verifier Token"
export TOKEN_SYMBOL="BVT"
```

**Deploy:**
```sh
forge script script/Deploy.s.sol:Deploy --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast -vvv
```

The deploy script prints the deployed contract address.

---

### Example interactions

#### Interaction 1 — Full "Task 5 flow" demo (deploy + submit header + verify tx)

This uses the provided fixtures:

```sh
export HEADER_HEX_PATH="test/fixtures/sample_header.hex"
export TX_HEX_PATH="test/fixtures/sample_tx.hex"
export PROOF_JSON_PATH="test/fixtures/sample_proof.json"
export TX_INDEX="4"
export BLOCK_HASH="0x0000000000000000000226ab487ff1a8456a30feb1bde3d65b6a67128074e19a"

forge script script/DemoFlow.s.sol:DemoFlow --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast -vvv
```

You should see logs confirming:
- header accepted
- block known + height assigned
- transaction verified
- mint succeeded

#### Interaction 2 — Query minted balance (cast)

After DemoFlow, the minted recipient is the pseudo-recipient derived from TARGET_PKH.
In this implementation, it is simply the Ethereum-style address with the same 20 bytes as TARGET_PKH:

```sh
export RECIP="0x91FF9f2Eed45fe06FaB4875DF1BD40B1d77D1bFc"
```

Set TOKEN to the deployed contract address printed by Deploy/DemoFlow:

```sh
export TOKEN="0xYOUR_DEPLOYED_CONTRACT_ADDRESS"

cast call "$TOKEN" "totalSupply()(uint256)" --rpc-url "$RPC_URL"
cast call "$TOKEN" "balanceOf(address)(uint256)" "$RECIP" --rpc-url "$RPC_URL"
```

---

### Option B — Public testnet deployment

Set:

```sh
export RPC_URL="https://YOUR_RPC_URL"
export PRIVATE_KEY="0xYOUR_PRIVATE_KEY"

export CHECKPOINT_HASH="0x..."
export CHECKPOINT_HEIGHT="..."
export TARGET_PKH="0x..."   # 20-byte HASH160 (0x + 40 hex chars)
```

Deploy:

```sh
forge script script/Deploy.s.sol:Deploy --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast -vvv
```

(Optional) contract verification (if you are using a supported explorer and have an API key):

```sh
export ETHERSCAN_KEY="YOUR_KEY"
forge script script/Deploy.s.sol:Deploy --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast --verify --etherscan-api-key "$ETHERSCAN_KEY" -vvv
```

## Notes (Task 4 requirement: PKH vs Ethereum address)

The contract mints tokens to a pseudo-address derived from the 20-byte Bitcoin `pubKeyHash` (HASH160). This is not a trustless mapping to a real Ethereum wallet. See `docs/TASK4.md` for the required explanation and proposed improvements (claim flows / signatures / oracle attestations).