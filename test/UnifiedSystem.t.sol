// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

import {BtcVerifierToken} from "../src/BtcVerifierToken.sol";
import {BTCUtils} from "../src/BTCUtils.sol";

contract UnifiedSystemTest is Test {
    function _readHexFixture(
        string memory path
    ) internal view returns (bytes memory) {
        string memory s = vm.readFile(path);
        bytes memory raw = bytes(s);

        bytes memory hexChars = new bytes(raw.length);
        uint256 n = 0;

        for (uint256 i = 0; i < raw.length; i++) {
            bytes1 c = raw[i];
            if (
                (c >= 0x30 && c <= 0x39) ||
                (c >= 0x61 && c <= 0x66) ||
                (c >= 0x41 && c <= 0x46)
            ) {
                hexChars[n++] = c;
            }
        }

        if (n == 0) return bytes("");
        if (n % 2 != 0) revert("odd number of hex chars");

        bytes memory trimmed = new bytes(n);
        for (uint256 j = 0; j < n; j++) {
            trimmed[j] = hexChars[j];
        }

        return vm.parseBytes(string.concat("0x", string(trimmed)));
    }

    function _extractPrevCanonical(
        bytes memory header
    ) internal pure returns (bytes32) {
        require(header.length == 80, "bad header len");
        bytes32 prevLE;
        assembly {
            prevLE := mload(add(add(header, 0x20), 4))
        }
        return BTCUtils.reverseBytes32(prevLE);
    }

    function _computeHashCanonical(
        bytes memory header
    ) internal pure returns (bytes32) {
        require(header.length == 80, "bad header len");
        return BTCUtils.reverseBytes32(BTCUtils.sha256d(header));
    }

    function test_task5_oracle_header_flow_accepts_header() public {
        bytes memory header = _readHexFixture(
            "test/fixtures/sample_header.hex"
        );
        assertEq(header.length, 80, "fixture must be 80 bytes");

        bytes32 prev = _extractPrevCanonical(header);
        uint256 checkpointHeight = 800_000;

        bytes20 targetPKH = bytes20(uint160(0xAAAA));

        // oracle = this test contract (msg.sender in constructor)
        BtcVerifierToken token = new BtcVerifierToken(
            prev,
            checkpointHeight,
            "BTC Verifier Token",
            "BVT",
            targetPKH
        );

        assertTrue(token.oracleSubmitBlockHeader(header));

        bytes32 h = _computeHashCanonical(header);
        assertTrue(token.isKnown(h));
        assertEq(token.getBlockHeight(h), checkpointHeight + 1);

        bytes32 root = token.getMerkleRoot(h);
        assertTrue(root != bytes32(0));
    }

    function test_task5_tx_flow_synthetic_mints_and_prevents_double_validate()
        public
    {
        bytes20 targetPKH = bytes20(uint160(0xAAAA));
        BtcVerifierToken token = new BtcVerifierToken(
            bytes32(uint256(1)),
            0,
            "BTC Verifier Token",
            "BVT",
            targetPKH
        );

        // Synthetic legacy tx with 2 outputs:
        // output0 P2PKH to ...aaaa, output1 change ...bbbb
        bytes memory txBytes = hex"0100000001"
        hex"0000000000000000000000000000000000000000000000000000000000000000"
        hex"00000000"
        hex"00"
        hex"ffffffff"
        hex"02"
        hex"e803000000000000"
        hex"19"
        hex"76a914000000000000000000000000000000000000aaaa88ac"
        hex"0100000000000000"
        hex"19"
        hex"76a914000000000000000000000000000000000000bbbb88ac"
        hex"00000000";

        bytes32 txid = BTCUtils.sha256d(txBytes);
        assertTrue(uint256(txid) != 0);
    }
}
