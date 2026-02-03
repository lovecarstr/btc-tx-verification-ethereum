// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import "../src/BTCUtils.sol";

/// @dev Harness to expose BTCUtils internal library functions to tests.
contract BTCUtilsHarness {
    using BTCUtils for bytes;

    function sha256d(bytes memory data) external pure returns (bytes32) {
        return BTCUtils.sha256d(data);
    }

    function reverseBytes32(bytes32 x) external pure returns (bytes32) {
        return BTCUtils.reverseBytes32(x);
    }

    function readUint32LE(bytes memory data, uint256 offset) external pure returns (uint32) {
        return BTCUtils.readUint32LE(data, offset);
    }

    function readUint64LE(bytes memory data, uint256 offset) external pure returns (uint64) {
        return BTCUtils.readUint64LE(data, offset);
    }

    function readVarInt(bytes memory data, uint256 offset) external pure returns (uint64, uint256) {
        return BTCUtils.readVarInt(data, offset);
    }

    function slice(bytes memory data, uint256 offset, uint256 len) external pure returns (bytes memory) {
        return BTCUtils.slice(data, offset, len);
    }
}

contract BTCUtilsTest is Test {
    BTCUtilsHarness internal h;

    function setUp() public {
        h = new BTCUtilsHarness();
    }

    // ---------------- sha256d ----------------

    function test_sha256d_knownVector_abc() public {
        bytes memory input = bytes("abc");
        bytes32 expected = hex"4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358";
        assertEq(h.sha256d(input), expected);
    }

    // Optional: add empty input or another known vector
    function test_sha256d_knownVector_empty() public {
        bytes memory input = hex"";
        bytes32 expected = hex"5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456";
        assertEq(h.sha256d(input), expected);
    }

    // ---------------- reverseBytes32 ----------------

    function test_reverseBytes32_knownVector_incrementing() public {
        bytes32 input = hex"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        bytes32 expected = hex"1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
        assertEq(h.reverseBytes32(input), expected);
    }

    // ---------------- readUint32LE ----------------

    function test_readUint32LE_basic() public {
        // bytes: 01 02 03 04 (little-endian) => 0x04030201
        bytes memory data = hex"01020304";
        assertEq(h.readUint32LE(data, 0), uint32(0x04030201));

        // Another common check: 78 56 34 12 => 0x12345678
        bytes memory data2 = hex"78563412";
        assertEq(h.readUint32LE(data2, 0), uint32(0x12345678));
    }

    function test_readUint32LE_revertsOnOOB() public {
        // only 3 bytes, but readUint32LE needs 4
        bytes memory data = hex"785634";

        vm.expectRevert(
            abi.encodeWithSelector(BTCUtils.BTCUtils__OutOfBounds.selector, uint256(0), uint256(4), uint256(3))
        );
        h.readUint32LE(data, 0);
    }

    // ---------------- readUint64LE ----------------

    function test_readUint64LE_basic() public {
        // 01 02 03 04 05 06 07 08 (LE) => 0x0807060504030201
        bytes memory data = hex"0102030405060708";
        assertEq(h.readUint64LE(data, 0), uint64(0x0807060504030201));

        // Another sanity: 78 56 34 12 00 00 00 00 => 0x0000000012345678
        bytes memory data2 = hex"7856341200000000";
        assertEq(h.readUint64LE(data2, 0), uint64(0x0000000012345678));
    }

    function test_readUint64LE_revertsOnOOB() public {
        // only 7 bytes, but need 8
        bytes memory data = hex"01020304050607";

        vm.expectRevert(
            abi.encodeWithSelector(BTCUtils.BTCUtils__OutOfBounds.selector, uint256(0), uint256(8), uint256(7))
        );
        h.readUint64LE(data, 0);
    }

    // ---------------- readVarInt ----------------

    function test_readVarInt_1byte() public {
        bytes memory data = hex"fc"; // 252
        (uint64 v, uint256 next) = h.readVarInt(data, 0);
        assertEq(v, 252);
        assertEq(next, 1);
    }

    function test_readVarInt_0xfd_2bytes() public {
        // 0xFD followed by LE uint16 0x00FD (=253)
        bytes memory data = hex"fdfd00";
        (uint64 v, uint256 next) = h.readVarInt(data, 0);
        assertEq(v, 253);
        assertEq(next, 3);
    }

    function test_readVarInt_0xfe_4bytes() public {
        // 0xFE followed by LE uint32 0x00010000 (=65536)
        bytes memory data = hex"fe00000100";
        (uint64 v, uint256 next) = h.readVarInt(data, 0);
        assertEq(v, 65536);
        assertEq(next, 5);
    }

    function test_readVarInt_0xff_8bytes() public {
        // 0xFF followed by LE uint64 0x0000000100000000 (=4294967296)
        bytes memory data = hex"ff0000000001000000";
        (uint64 v, uint256 next) = h.readVarInt(data, 0);
        assertEq(v, 4294967296);
        assertEq(next, 9);
    }

    function test_readVarInt_revertsOnInsufficientPayload() public {
        // 0xFD requires 2 payload bytes, but only 1 provided
        bytes memory data = hex"fd01";

        vm.expectRevert(
            abi.encodeWithSelector(
                BTCUtils.BTCUtils__OutOfBounds.selector,
                uint256(1), // payload starts at offset+1
                uint256(2),
                uint256(2)
            )
        );
        h.readVarInt(data, 0);
    }

    function test_readVarInt_revertsOnNonCanonicalEncoding_ifEnabled() public {
        // Non-canonical: 0xFD used to encode value 1 (< 0xFD)
        bytes memory data = hex"fd0100";

        vm.expectRevert(abi.encodeWithSelector(BTCUtils.BTCUtils__BadVarInt.selector, uint256(0)));
        h.readVarInt(data, 0);
    }

    // ---------------- slice ----------------

    function test_slice_basic() public {
        bytes memory data = hex"001122334455";
        bytes memory out = h.slice(data, 1, 3);
        assertEq(out, hex"112233");
    }

    function test_slice_revertsOnOOB() public {
        bytes memory data = hex"001122334455"; // length 6

        vm.expectRevert(
            abi.encodeWithSelector(BTCUtils.BTCUtils__OutOfBounds.selector, uint256(4), uint256(3), uint256(6))
        );
        h.slice(data, 4, 3);
    }
}
