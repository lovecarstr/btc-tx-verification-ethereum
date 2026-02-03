# ICT3009 — Bitcoin Transaction Verification on Ethereum (Solidity + Foundry)

This repository contains my coursework implementation for **ICT3009**, built in **Solidity** and tested using **Foundry**.

Implemented features (Tasks 1–4):
- Bitcoin utilities: double-SHA256, endianness helpers, VarInt parsing
- Bitcoin-style Merkle proof verification (double-SHA256 parent hashing)
- Bitcoin block header chain verification that stores **only block hashes** + heights (not full headers)
- ERC-20 token (initial supply = 0, internal mint, burn support)
- Transaction verification that proves a **P2PKH or P2PK** transaction output is included in a known block, then mints ERC-20 tokens equal to the output value (satoshis)

---

## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:
- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools)
- **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data
- **Anvil**: Local Ethereum node, akin to Ganache / Hardhat Network
- **Chisel**: Fast Solidity REPL

### Documentation
https://book.getfoundry.sh/

---

## Project structure

### Contracts (`src/`)
- `BTCUtils.sol`  
  Bitcoin helper library: `sha256d`, `reverseBytes32`, LE reads, VarInt parsing, slice helpers.

- `MerkleProofBTC.sol`  
  Verifies Bitcoin-style Merkle proofs using double-SHA256 at each parent.

- `BitcoinHeaderChain.sol`  
  **Task 2**: accepts 80-byte Bitcoin headers and stores only:
  - `blockHash -> height`
  - `blockHash -> merkleRoot` (needed for Task 4)
  
  Verifies:
  - header length = 80 bytes
  - `prevBlockHash` references a previously stored block
  - difficulty target from `bits`
  - PoW: `hash <= target`
  - minimum difficulty requirement (70 billion)

- `BtcVerifierToken.sol`  
  **Task 3 + Task 4**: ERC-20 + verify-and-mint logic  
  Includes:
  - ERC-20: `totalSupply`, `balanceOf`, `transfer`, `approve`, `allowance`, `transferFrom`, `Transfer`, `Approval`
  - initial supply = **0**
  - minting is **internal** (triggered by verification, not user-callable)
  - burn + optional burnFrom
  - **Task 4**: `verifyTransaction(...)` (required signature) and optional `verifyTransactionTo(...)`

### Tests (`test/`)
- `BTCUtils.t.sol` — BTC utils tests
- `MerkleProof.t.sol` — Merkle proof verifier tests
- `HeaderChain.t.sol` — block header submission / chaining / PoW tests
- `BtcVerifierToken.t.sol` — ERC-20 tests
- `VerifyTransaction.t.sol` — Task 4 transaction verification tests (P2PKH/P2PK, segwit txid stripping, double validation prevention, etc.)

### Docs (`docs/`)
- `docs/TASK4.md` — Task 4 write-up, including the required note about PKH vs Ethereum addresses and suggested improvements

---

## Endianness conventions used

Bitcoin serialization uses little-endian in multiple places, so this repo uses explicit conventions:

- **Stored block hashes** are **canonical/explorer-style** bytes32:
  - `blockHashCanonical = reverseBytes32(sha256d(header))`

- The block’s **Merkle root** is stored **exactly as it appears in the header field** (internal order / header byte order).

- Transaction ID used in Merkle proof verification:
  - **Legacy txid** = `sha256d(fullTxBytes)`
  - **SegWit txid** = `sha256d(strippedSerializationWithoutWitness)`  
    (marker/flag and witness are excluded from txid)

Merkle verification expects all hashes passed in the same byte order that the hashing uses.

---

## Task coverage summary

### Task 1 — Merkle proof verifier
Implemented in `MerkleProofBTC.sol` and tested in `test/MerkleProof.t.sol`.

### Task 2 — Bitcoin block header verification system
Implemented in `BitcoinHeaderChain.sol` and tested in `test/HeaderChain.t.sol`.
- Accepts 80-byte headers
- Computes block hash (double SHA256 + correct endianness)
- Decodes `bits` → target, verifies PoW
- Enforces minimum difficulty requirement (70B)
- Verifies chaining via `prevBlockHash`
- Maintains `hash -> height`
- Stores each block’s Merkle root for Task 4

### Task 3 — ERC-20 token
Implemented in `BtcVerifierToken.sol` and tested in `test/BtcVerifierToken.t.sol`.
- ERC-20 compliant interface and events
- initial supply = 0
- mint is internal only
- burn support

### Task 4 — Verify P2PKH/P2PK tx inclusion + mint ERC-20
Implemented in `BtcVerifierToken.sol` and tested in `test/VerifyTransaction.t.sol`.
- Validates `blockHash` is known
- Verifies Merkle proof using Task 1
- Prevents validating the same tx twice
- Parses transaction and requires exactly **2 outputs**
- Validates output0 scriptPubKey is **P2PKH** or **P2PK**
- Mints tokens equal to output0 value (satoshis) to address derived from output0 PKH
- Optional helper `verifyTransactionTo(...)` enforces an expected PKH while keeping required signature intact

---

## Usage

### Build
```shell
forge build
