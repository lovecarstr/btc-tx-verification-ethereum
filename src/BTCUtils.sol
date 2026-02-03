// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BTCUtils
/// @notice Minimal Bitcoin byte parsing + hashing helpers for ICT3009.
/// @dev Explicit about Bitcoin endianness:
///      - Many numeric fields are little-endian (LE): uint32, uint64, VarInt payloads.
///      - 32-byte hashes in serialized data (like header.prevBlock / merkleRoot) are typically LE.
///        In Solidity, bytes32 returned by sha256 is the raw digest bytes (big-endian “normal” digest ordering).
///        You will often need reverseBytes32 when converting between “wire bytes” and “digest bytes”.
library BTCUtils {
    // ----------- Custom errors -----------

    /// @notice Thrown when attempting to read beyond data.length.
    /// @param offset Starting offset requested
    /// @param need Number of bytes required
    /// @param length data.length
    error BTCUtils__OutOfBounds(uint256 offset, uint256 need, uint256 length);

    /// @notice Thrown when VarInt prefix is invalid or the payload is not canonical/complete.
    /// @param offset Where VarInt parsing began
    error BTCUtils__BadVarInt(uint256 offset);

    // ----------- Hashing -----------

    /// @notice Bitcoin double SHA256: sha256(sha256(data)).
    /// @dev Used for: block hash, txid, Merkle nodes.
    /// @param data Arbitrary byte array
    /// @return digest Double-SHA256 digest as bytes32
    function sha256d(bytes memory data) internal pure returns (bytes32 digest) {
        bytes32 h1 = sha256(data);
        digest = sha256(abi.encodePacked(h1));
    }

    // ----------- Endianness -----------

    /// @notice Reverse byte order of a bytes32.
    /// @dev Useful to convert Bitcoin serialized (little-endian) hash bytes into digest-order bytes32 (and vice versa).
    /// @param x Input bytes32
    /// @return y Reversed bytes32
    function reverseBytes32(bytes32 x) internal pure returns (bytes32 y) {
        bytes memory b = abi.encodePacked(x); // 32 bytes, b[0] is MSB of x
        uint256 r;

        // Place b[0] into least-significant byte, b[31] into most-significant byte
        for (uint256 i = 0; i < 32; i++) {
            r |= uint256(uint8(b[i])) << (8 * i);
        }

        y = bytes32(r);
    }

    // ----------- Fixed-width reads (Little-Endian) -----------

    /// @notice Read 4 bytes as little-endian uint32 from `data` at `offset`.
    /// @dev Bitcoin header fields version/time/bits/nonce are LE uint32.
    function readUint32LE(bytes memory data, uint256 offset) internal pure returns (uint32 value) {
        _requireAvailable(data, offset, 4);
        // Little-endian: lowest byte first.
        value = uint32(uint8(data[offset])) | (uint32(uint8(data[offset + 1])) << 8)
            | (uint32(uint8(data[offset + 2])) << 16) | (uint32(uint8(data[offset + 3])) << 24);
    }

    /// @notice Read 8 bytes as little-endian uint64 from `data` at `offset`.
    /// @dev Bitcoin tx output values are LE uint64 (satoshis).
    function readUint64LE(bytes memory data, uint256 offset) internal pure returns (uint64 value) {
        _requireAvailable(data, offset, 8);

        value = uint64(uint8(data[offset])) | (uint64(uint8(data[offset + 1])) << 8)
            | (uint64(uint8(data[offset + 2])) << 16) | (uint64(uint8(data[offset + 3])) << 24)
            | (uint64(uint8(data[offset + 4])) << 32) | (uint64(uint8(data[offset + 5])) << 40)
            | (uint64(uint8(data[offset + 6])) << 48) | (uint64(uint8(data[offset + 7])) << 56);
    }

    // ----------- VarInt -----------

    /// @notice Parse Bitcoin VarInt starting at `offset`.
    /// @dev Encoding:
    ///      - < 0xFD: 1 byte
    ///      - 0xFD: next 2 bytes (LE) as uint16
    ///      - 0xFE: next 4 bytes (LE) as uint32
    ///      - 0xFF: next 8 bytes (LE) as uint64
    /// @return value Parsed value (uint64)
    /// @return newOffset Offset immediately after the VarInt
    function readVarInt(bytes memory data, uint256 offset) internal pure returns (uint64 value, uint256 newOffset) {
        _requireAvailable(data, offset, 1);
        uint8 prefix = uint8(data[offset]);

        // 1-byte case
        if (prefix < 0xFD) {
            value = uint64(prefix);
            newOffset = offset + 1;
            return (value, newOffset);
        }

        // 0xFD => next 2 bytes LE (uint16)
        if (prefix == 0xFD) {
            _requireAvailable(data, offset + 1, 2);

            uint16 v = uint16(uint8(data[offset + 1])) | (uint16(uint8(data[offset + 2])) << 8);

            // canonical: 0xFD must encode >= 0xFD
            if (v < 0xFD) revert BTCUtils__BadVarInt(offset);

            value = uint64(v);
            newOffset = offset + 3;
            return (value, newOffset);
        }

        // 0xFE => next 4 bytes LE (uint32)
        if (prefix == 0xFE) {
            _requireAvailable(data, offset + 1, 4);

            uint32 v32 = readUint32LE(data, offset + 1);

            // canonical: 0xFE must encode > 0xFFFF
            if (v32 <= 0xFFFF) revert BTCUtils__BadVarInt(offset);

            value = uint64(v32);
            newOffset = offset + 5;
            return (value, newOffset);
        }

        // 0xFF => next 8 bytes LE (uint64)
        // prefix == 0xFF
        _requireAvailable(data, offset + 1, 8);

        uint64 v64 = readUint64LE(data, offset + 1);

        // canonical: 0xFF must encode > 0xFFFFFFFF
        if (v64 <= 0xFFFFFFFF) revert BTCUtils__BadVarInt(offset);

        value = v64;
        newOffset = offset + 9;
    }

    // Slice

    /// @notice Copy `len` bytes from `data[offset..offset+len)` into a new bytes array.
    /// @dev Avoid in hot paths (allocations). Prefer manual reads with offsets in parsers.
    function slice(bytes memory data, uint256 offset, uint256 len) internal pure returns (bytes memory out) {
        _requireAvailable(data, offset, len);

        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = data[offset + i];
        }
    }

    // ----------- Shared helper -----------

    /// @dev Common bounds check helper (optional). Keep if it improves clarity.
    function _requireAvailable(bytes memory data, uint256 offset, uint256 need) internal pure {
        // TODO:
        if (offset > data.length || need > data.length - offset) {
            revert BTCUtils__OutOfBounds(offset, need, data.length);
        }
    }
}
