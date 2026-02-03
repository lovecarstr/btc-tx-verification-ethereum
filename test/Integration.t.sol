// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/StdJson.sol";

import {BtcVerifierToken} from "../src/BtcVerifierToken.sol";
import {BTCUtils} from "../src/BTCUtils.sol";

contract IntegrationTest is Test {
    using stdJson for string;

    function test_endToEnd_submitHeader_thenVerifyTx_thenMint() public {
        // --- Load header fixture (80 bytes) ---
        bytes memory header = _readHexBytes("test/fixtures/sample_header.hex");

        // Extract prevBlockHash (bytes 4..35) from header (little-endian in raw header)
        bytes32 prevLE;
        assembly {
            prevLE := mload(add(add(header, 0x20), 4))
        }

        // Your constructor expects checkpointHash in canonical/explorer style.
        bytes32 checkpointHash = BTCUtils.reverseBytes32(prevLE);

        // Height can be arbitrary for the test, just keep it consistent.
        uint256 checkpointHeight = 100;

        BtcVerifierToken token = new BtcVerifierToken(
            checkpointHash,
            checkpointHeight,
            "BTC Verifier Token",
            "BVT"
        );

        // Submit header via oracle entrypoint (if your build includes it); otherwise call submitBlockHeader directly.
        token.oracleSubmitBlockHeader(header);

        // Compute the submitted block hash (canonical/explorer style).
        bytes32 blockHash = BTCUtils.reverseBytes32(BTCUtils.sha256d(header));
        assertTrue(token.isKnown(blockHash), "block should be known after submit");

        // --- Load tx + proof fixtures ---
        bytes memory txBytes = _readHexBytes("test/fixtures/sample_tx.hex");

        string memory json = vm.readFile("test/fixtures/sample_proof.json");
        bytes32[] memory proof = abi.decode(json.parseRaw(".proof"), (bytes32[]));
        uint256 txIndex = json.readUint(".txIndex");
        address recipient = json.readAddress(".recipient");
        uint256 valueSats = json.readUint(".valueSats");

        // Sanity: fixture blockHash should match computed one (helps debugging endianness)
        bytes32 fixtureBlockHash = json.readBytes32(".blockHash");
        assertEq(fixtureBlockHash, blockHash, "fixture blockHash mismatch");

        // --- Verify and mint (use verifyTransactionTo if you want “specific recipient” enforced) ---
        // If you want strict recipient enforcement:
        // bytes20 expectedPKH = _readBytes20HexString(json.readString(".expectedPKH"));
        // assertTrue(token.verifyTransactionTo(txBytes, proof, txIndex, blockHash, expectedPKH));

        assertTrue(token.verifyTransaction(txBytes, proof, txIndex, blockHash));

        // Mint happened:
        assertEq(token.balanceOf(recipient), valueSats, "recipient should receive satoshi-denominated tokens");

        // Block height is consistent:
        uint256 h = token.getBlockHeight(blockHash);
        assertEq(h, checkpointHeight + 1, "height should be checkpoint+1");
    }

    // ---------- helpers ----------

    function _readHexBytes(string memory path) internal view returns (bytes memory) {
        string memory hexStr = _trim(vm.readFile(path));
        if (_startsWith0x(hexStr)) {
            return vm.parseBytes(hexStr);
        }
        return vm.parseBytes(string.concat("0x", hexStr));
    }

    function _trim(string memory s) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        uint256 start = 0;
        while (start < b.length && (b[start] == 0x0a || b[start] == 0x0d || b[start] == 0x20 || b[start] == 0x09)) start++;
        uint256 end = b.length;
        while (end > start && (b[end-1] == 0x0a || b[end-1] == 0x0d || b[end-1] == 0x20 || b[end-1] == 0x09)) end--;
        bytes memory out = new bytes(end - start);
        for (uint256 i = 0; i < out.length; i++) out[i] = b[start + i];
        return string(out);
    }

    function _startsWith0x(string memory s) internal pure returns (bool) {
        bytes memory b = bytes(s);
        return b.length >= 2 && b[0] == "0" && (b[1] == "x" || b[1] == "X");
    }
    
    function _readBytes20HexString(string memory s) internal view returns (bytes20 out) {
        bytes memory raw = vm.parseBytes(s); // must be 20 bytes
        require(raw.length == 20, "expectedPKH not 20 bytes");
        assembly {
            out := mload(add(raw, 0x20))
        }
    }
}
