// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BTCUtils} from "./BTCUtils.sol";

/// @title Bitcoin Block Header Verification System (Task 2)
/// @notice Stores only block hashes (canonical / explorer-style) and heights.
///         Accepts 80-byte Bitcoin headers, verifies PoW and chaining, enforces min difficulty.
///         Also stores each block's Merkle root (as a hash) for Task 4 inclusion proofs.
contract BitcoinHeaderChain {
    // --- Constants ---
    // Difficulty-1 target (bits = 0x1d00ffff)
    // 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    uint256 internal constant DIFF1_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000;

    // Minimum difficulty: 70,000,000,000
    uint256 internal constant MIN_DIFFICULTY = 70_000_000_000;

    // Enforce: target <= DIFF1_TARGET / MIN_DIFFICULTY
    // Precomputed exactly:
    // DIFF1_TARGET / 70,000,000,000 =
    // 0x00000000000000000fb5027e4482388eeb68535438766cc15954d88469af2b29
    uint256 internal constant MAX_TARGET_ALLOWED = 0x00000000000000000fb5027e4482388eeb68535438766cc15954d88469af2b29;

    // --- Storage ---
    mapping(bytes32 => uint256) private _heightOf; // canonicalHash -> height
    mapping(bytes32 => bool) private _known; // canonicalHash -> exists

    // NEW (for Task 4): store Merkle root per stored block hash.
    // Stored in the exact byte order present in the block header field (little-endian vs explorer display).
    mapping(bytes32 => bytes32) private _merkleRootOf; // canonicalHash -> merkleRootLE

    event HeaderAccepted(bytes32 indexed blockHash, bytes32 indexed prevHash, uint256 height);

    /// @param checkpointHash Canonical (explorer-style) block hash used as trusted anchor.
    /// @param checkpointHeight Height of checkpointHash.
    constructor(bytes32 checkpointHash, uint256 checkpointHeight) {
        _known[checkpointHash] = true;
        _heightOf[checkpointHash] = checkpointHeight;
    }

    /// @notice Submit and verify a Bitcoin block header (80 bytes).
    /// @dev Computes block hash = reverseBytes32(sha256d(header)).
    ///      Verifies prev hash is known, verifies PoW using bits->target, enforces min difficulty.
    ///      Stores merkle root (header field) for later inclusion checks (Task 4).
    function submitBlockHeader(bytes memory header) public returns (bool) {
        require(header.length == 80, "header must be 80 bytes");

        // Parse prevBlockHash (bytes 4..36), which is stored little-endian in the header.
        bytes32 prevLE = _readBytes32(header, 4);
        bytes32 prevCanonical = BTCUtils.reverseBytes32(prevLE);

        require(_known[prevCanonical], "unknown prev block");

        // Parse merkleRoot (bytes 36..68) as stored in header (LE/internal order).
        bytes32 merkleRootLE = _readBytes32(header, 36);

        // Compute sha256d(header) then reverse to canonical/explorer hash.
        bytes32 digest = BTCUtils.sha256d(header);
        bytes32 blockHashCanonical = BTCUtils.reverseBytes32(digest);

        require(!_known[blockHashCanonical], "block already known");

        // Parse bits (bytes 72..76) as little-endian uint32, decode to target.
        uint32 bitsLE = _readUint32LE(header, 72);
        uint256 target = _compactBitsToTarget(bitsLE);

        // Enforce minimum difficulty (i.e., target must be sufficiently small)
        require(target != 0, "invalid target");
        require(target <= MAX_TARGET_ALLOWED, "difficulty below 70B");

        // Verify PoW: hash as uint256 must be <= target.
        // We compare the canonical hash interpreted as a big-endian integer.
        require(uint256(blockHashCanonical) <= target, "insufficient PoW");

        // Store height
        uint256 newHeight = _heightOf[prevCanonical] + 1;
        _known[blockHashCanonical] = true;
        _heightOf[blockHashCanonical] = newHeight;

        // Store merkle root for Task 4 inclusion verification
        _merkleRootOf[blockHashCanonical] = merkleRootLE;

        emit HeaderAccepted(blockHashCanonical, prevCanonical, newHeight);
        return true;
    }

    /// @notice Return the height for a known block hash (canonical/explorer format).
    function getBlockHeight(bytes32 blockHash) public view returns (uint256) {
        require(_known[blockHash], "unknown block");
        return _heightOf[blockHash];
    }

    /// @notice Whether a block hash is known (canonical/explorer format).
    function isKnown(bytes32 blockHash) public view returns (bool) {
        return _known[blockHash];
    }

    /// @notice Merkle root for a known block hash, in the exact byte order stored in the header field.
    /// @dev This is used for Task 4 Merkle proof verification.
    function getMerkleRoot(bytes32 blockHash) public view returns (bytes32) {
        require(_known[blockHash], "unknown block");
        bytes32 root = _merkleRootOf[blockHash];
        require(root != bytes32(0), "merkle root unavailable");
        return root;
    }

    // ---------------------------
    // Internal helpers
    // ---------------------------

    /// @dev INTERNAL TEST HOOK (not externally callable).
    ///      Lets a derived test harness mark blocks as known and set merkle roots.
    function _setKnownBlockForTest(bytes32 blockHash, uint256 height, bytes32 merkleRootLE) internal {
        _known[blockHash] = true;
        _heightOf[blockHash] = height;
        _merkleRootOf[blockHash] = merkleRootLE;
    }

    /// @dev Read bytes32 from `data` at `offset` (expects >= offset+32).
    function _readBytes32(bytes memory data, uint256 offset) internal pure returns (bytes32 out) {
        require(data.length >= offset + 32, "readBytes32 oob");
        assembly {
            out := mload(add(add(data, 0x20), offset))
        }
    }

    /// @dev Read little-endian uint32 from `data` at `offset` (expects >= offset+4).
    function _readUint32LE(bytes memory data, uint256 offset) internal pure returns (uint32) {
        require(data.length >= offset + 4, "readUint32LE oob");
        uint32 b0 = uint8(data[offset]);
        uint32 b1 = uint8(data[offset + 1]);
        uint32 b2 = uint8(data[offset + 2]);
        uint32 b3 = uint8(data[offset + 3]);
        return (b0) | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }

    /// @dev Convert Bitcoin compact "bits" into a full 256-bit target.
    /// Format: [exponent (1 byte)] [mantissa (3 bytes)] in big-endian within the 32-bit value.
    /// We already read bits as uint32 from little-endian bytes, so bitsLE now has the same bit layout
    /// as Bitcoin's nBits value.
    function _compactBitsToTarget(uint32 bitsLE) internal pure returns (uint256) {
        uint32 exponent = bitsLE >> 24;
        uint32 mantissa = bitsLE & 0x00FFFFFF;

        // Reject negative compact representation (sign bit set)
        // In Bitcoin, mantissa's highest bit (0x00800000) indicates "negative".
        require((mantissa & 0x00800000) == 0, "compact negative");
        require(mantissa != 0, "compact zero mantissa");
        require(exponent <= 32, "compact exponent too large");

        if (exponent <= 3) {
            uint32 shift = 8 * (3 - exponent);
            return uint256(mantissa) >> shift;
        } else {
            uint32 shift = 8 * (exponent - 3);
            return uint256(mantissa) << shift;
        }
    }
}
