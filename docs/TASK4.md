# Task 4 — Verify P2PKH/P2PK transaction inclusion + mint ERC-20

## Goal (Task 4)
Implement a function that lets a user prove a Bitcoin transaction was included in a previously submitted Bitcoin block (Task 2), **verify** that the transaction’s **first output** pays to a **specific Bitcoin address** (P2PKH or P2PK), **prevent double validation**, and then **mint ERC-20 tokens** equal to the output amount (in satoshis).

### Required interface (spec)
- `verifyTransaction(bytes transaction, bytes32[] merkleProof, uint256 txIndex, bytes32 blockHash)`

---

## Endianness conventions used
Bitcoin serialization uses little-endian for several fields, so this project uses explicit conventions:

- **Stored block hashes** in `BitcoinHeaderChain` are canonical/explorer-style:  
  `blockHashCanonical = reverseBytes32(sha256d(header))`

- The **Merkle root** stored from the header is kept **exactly as it appears in the header field bytes** (internal byte order).  
  Merkle proof verification uses this stored root consistently with how hashes are combined in the verifier.

- **Transaction IDs** used for Merkle proof verification are computed as:  
  `txid = sha256d(serializedTx)`  
  - **Legacy txid:** hashes the full raw transaction bytes.  
  - **SegWit txid:** hashes the **stripped** serialization (excludes marker/flag and witness).

---

## Verification steps (implementation summary)
1. **Validate `blockHash` is known**  
   Ensure the block hash exists in the contract (was accepted in Task 2).

2. **Load Merkle root for that block**  
   Retrieve `merkleRootLE` stored when the header was submitted.

3. **Compute txid (legacy vs SegWit rules)**  
   - If non-SegWit: `sha256d(fullTxBytes)`  
   - If SegWit: `sha256d(strippedSerializationWithoutWitness)`

4. **Verify Merkle inclusion**  
   Call Task 1 verifier:  
   `verifyMerkleProof(merkleProof, merkleRootLE, txid, txIndex)`  
   Revert if false.

5. **Prevent double validation**  
   Maintain `validatedTx[txid]`.  
   Revert if `validatedTx[txid] == true`, else set it true.

6. **Parse and validate the transaction structure**
   - Parse input count with VarInt and skip each input safely (bounds checks).
   - Parse output count with VarInt and **require exactly 2 outputs** (receiver + change).
   - Read **output 0**:
     - value: `uint64` little-endian (satoshis)
     - scriptPubKey: VarInt length + bytes
   - Accept script types:
     - **P2PKH:** `76a914{20-byte PKH}88ac`
     - **P2PK:** `21{33-byte pubkey}ac` or `41{65-byte pubkey}ac`  
       Derive `PKH = RIPEMD160(SHA256(pubkey))`

7. **Enforce “specific Bitcoin address” requirement**
   Compare extracted `pubKeyHash` against the configured target:  
   `require(pubKeyHash == TARGET_PKH, "wrong recipient")`

8. **Mint ERC-20 tokens equal to satoshis**
   Mint `valueSats` tokens (decimals = 8) to a pseudo-recipient derived from the 20-byte PKH.

---

## Spec note: why you can’t produce a matching Ethereum address from a Bitcoin PKH
A Bitcoin P2PKH “public key hash” is:

- `PKH = RIPEMD160(SHA256(pubkey))` (20 bytes)

An Ethereum address is derived as:

- `ethAddress = last20bytes(keccak256(uncompressed_pubkey))`

These are fundamentally different mappings and hash functions. There is no general trustless method to convert a Bitcoin PKH into “the” rightful Ethereum address. A 20-byte value can be interpreted as an Ethereum address format-wise, but that does not imply anyone controls the corresponding Ethereum private key.

Therefore, minting to a “pseudo-address” derived from PKH is only an accounting mechanism unless an explicit claim/ownership mapping is added.

---

## Suggested improvement: claim / mapping mechanism (recommended)
Add a **claim** flow to link Bitcoin key ownership to an Ethereum address:

1. User submits:
   - Bitcoin public key (or provably associated pubkey),
   - a Bitcoin signature over a fixed claim message (e.g., contract address + chain id + ethRecipient),
   - the desired Ethereum recipient address.

2. Contract verifies:
   - `hash160(pubkey) == creditedPKH`,
   - signature is valid for that pubkey and message.

3. Contract records mapping:
   - `pkh -> ethRecipient`

4. Contract allows:
   - transfer/withdrawal/redirect of tokens from the pseudo-recipient to `ethRecipient`.

This links ownership of the Bitcoin private key to a chosen Ethereum address in a verifiable way.
