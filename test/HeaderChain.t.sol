// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

import {BitcoinHeaderChain} from "../src/BitcoinHeaderChain.sol";
import {BTCUtils} from "../src/BTCUtils.sol";

contract HeaderChainTest is Test {
    function _readHexFixture(string memory path) internal view returns (bytes memory) {
        // 1) If the fixture is actually raw bytes, this is the best path.
        //    (Some people store "sample_header.hex" but it's really binary.)
        bytes memory bin = vm.readFileBinary(path);
        if (bin.length == 80) return bin;

        // 2) Otherwise parse as text hex, but be robust: remove everything except hex chars.
        string memory s = vm.readFile(path);
        bytes memory raw = bytes(s);

        bytes memory hexChars = new bytes(raw.length);
        uint256 n = 0;

        for (uint256 i = 0; i < raw.length; i++) {
            bytes1 c = raw[i];
            if (
                (c >= 0x30 && c <= 0x39) // 0-9
                    || (c >= 0x61 && c <= 0x66) // a-f
                    || (c >= 0x41 && c <= 0x46) // A-F
            ) {
                hexChars[n] = c;
                n++;
            }
        }

        require(n > 0, "fixture empty or not hex");

        // Copy into exact-size array
        bytes memory trimmed = new bytes(n);
        for (uint256 j = 0; j < n; j++) {
            trimmed[j] = hexChars[j];
        }

        // Must be even number of hex chars
        require(n % 2 == 0, "odd number of hex chars");

        // Parse into bytes
        bytes memory out = vm.parseBytes(string.concat("0x", string(trimmed)));

        return out;
    }

    function _extractPrevCanonical(bytes memory header) internal pure returns (bytes32) {
        require(header.length == 80, "bad header len");
        bytes32 prevLE;
        assembly {
            prevLE := mload(add(add(header, 0x20), 4))
        }
        return BTCUtils.reverseBytes32(prevLE);
    }

    function _computeHashCanonical(bytes memory header) internal pure returns (bytes32) {
        require(header.length == 80, "bad header len");
        bytes32 digest = BTCUtils.sha256d(header);
        return BTCUtils.reverseBytes32(digest);
    }

    function test_submit_validHeader_storesHeight() public {
        bytes memory header = _readHexFixture("test/fixtures/sample_header.hex");
        assertEq(header.length, 80, "fixture must be 80 bytes");

        bytes32 prev = _extractPrevCanonical(header);

        uint256 checkpointHeight = 800_000; // any number is fine for this test
        BitcoinHeaderChain chain = new BitcoinHeaderChain(prev, checkpointHeight);

        bool ok = chain.submitBlockHeader(header);
        assertTrue(ok);

        bytes32 h = _computeHashCanonical(header);
        assertTrue(chain.isKnown(h));
        assertEq(chain.getBlockHeight(h), checkpointHeight + 1);
    }

    function test_submit_rejectsWrongLength() public {
        bytes memory bad = hex"00";
        BitcoinHeaderChain chain = new BitcoinHeaderChain(bytes32(uint256(1)), 123);
        vm.expectRevert("header must be 80 bytes");
        chain.submitBlockHeader(bad);
    }

    function test_submit_rejectsUnknownPrev() public {
        bytes memory header = _readHexFixture("test/fixtures/sample_header.hex");
        bytes32 wrongCheckpoint = bytes32(uint256(0xBEEF));
        BitcoinHeaderChain chain = new BitcoinHeaderChain(wrongCheckpoint, 100);

        vm.expectRevert("unknown prev block");
        chain.submitBlockHeader(header);
    }

    function test_submit_rejectsDuplicate() public {
        bytes memory header = _readHexFixture("test/fixtures/sample_header.hex");
        bytes32 prev = _extractPrevCanonical(header);

        BitcoinHeaderChain chain = new BitcoinHeaderChain(prev, 900);

        assertTrue(chain.submitBlockHeader(header));

        vm.expectRevert("block already known");
        chain.submitBlockHeader(header);
    }

    function test_submit_rejectsInvalidPowByChangingNonce() public {
        bytes memory header = _readHexFixture("test/fixtures/sample_header.hex");
        bytes32 prev = _extractPrevCanonical(header);

        BitcoinHeaderChain chain = new BitcoinHeaderChain(prev, 500);

        // Mutate last byte (nonce) - almost certainly breaks PoW deterministically
        header[79] = bytes1(uint8(header[79]) ^ 0x01);

        vm.expectRevert("insufficient PoW");
        chain.submitBlockHeader(header);
    }

    function test_getBlockHeight_unknownReverts() public {
        BitcoinHeaderChain chain = new BitcoinHeaderChain(bytes32(uint256(1)), 1);
        vm.expectRevert("unknown block");
        chain.getBlockHeight(bytes32(uint256(2)));
    }
}
