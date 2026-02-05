// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {BtcVerifierToken} from "../src/BtcVerifierToken.sol";
import {BTCUtils} from "../src/BTCUtils.sol";

/// Env vars
/// Required:
/// - PRIVATE_KEY
/// - CHECKPOINT_HASH
/// - CHECKPOINT_HEIGHT
/// - TARGET_PKH  (0x + 40 hex chars, or 0x + 64 hex chars)
///
/// Optional:
/// - TOKEN_NAME
/// - TOKEN_SYMBOL
/// - HEADER_HEX_PATH    (e.g. test/fixtures/sample_header.hex)
/// - TX_HEX_PATH        (e.g. test/fixtures/sample_tx.hex)
/// - PROOF_JSON_PATH    (e.g. test/fixtures/sample_proof.json)  JSON: { "proof": ["0x..", ...] }
/// - TX_INDEX
/// - BLOCK_HASH         (canonical/explorer hash, bytes32)
contract DemoFlow is Script {
    // -------- env helpers --------
    function _envBytes20(
        string memory key
    ) internal view returns (bytes20 out) {
        string memory s = vm.envString(key);

        bytes memory b = bytes(s);
        require(
            b.length >= 2 && b[0] == "0" && (b[1] == "x" || b[1] == "X"),
            "env must be 0x-prefixed"
        );

        if (b.length == 42) {
            bytes memory parsed = vm.parseBytes(s);
            require(parsed.length == 20, "env must decode to 20 bytes");
            assembly {
                out := mload(add(parsed, 0x20))
            }
            return out;
        }

        if (b.length == 66) {
            bytes32 v = vm.parseBytes32(s);
            return bytes20(v);
        }

        revert("env length must be 42 (bytes20) or 66 (bytes32)");
    }

    function _pkhToAddress(bytes20 pkh) internal pure returns (address) {
        return address(uint160(uint256(bytes32(pkh)) >> 96));
    }

    // -------- file helpers --------
    function _readHexFixture(
        string memory path
    ) internal view returns (bytes memory) {
        // Reads a file containing "0x..." or raw hex with whitespace/newlines and parses it into bytes.
        string memory s = vm.readFile(path);
        bytes memory raw = bytes(s);

        bytes memory hexChars = new bytes(raw.length);
        uint256 n = 0;

        for (uint256 i = 0; i < raw.length; i++) {
            bytes1 c = raw[i];
            if (
                (c >= 0x30 && c <= 0x39) || // 0-9
                (c >= 0x61 && c <= 0x66) || // a-f
                (c >= 0x41 && c <= 0x46) // A-F
            ) {
                hexChars[n++] = c;
            }
        }

        require(n > 0, "fixture empty");
        require(n % 2 == 0, "odd number of hex chars");

        bytes memory trimmed = new bytes(n);
        for (uint256 j = 0; j < n; j++) trimmed[j] = hexChars[j];

        return vm.parseBytes(string.concat("0x", string(trimmed)));
    }

    function _readProofFromJson(
        string memory jsonPath
    ) internal view returns (bytes32[] memory proof) {
        // expects: { "proof": ["0x..", "0x..", ...] }
        string memory json = vm.readFile(jsonPath);
        proof = vm.parseJsonBytes32Array(json, ".proof");
    }

    function run() external returns (BtcVerifierToken token) {
        uint256 pk = vm.envUint("PRIVATE_KEY");

        bytes32 checkpointHash = vm.envBytes32("CHECKPOINT_HASH");
        uint256 checkpointHeight = vm.envUint("CHECKPOINT_HEIGHT");
        bytes20 targetPKH = _envBytes20("TARGET_PKH");

        string memory name_ = vm.envOr(
            "TOKEN_NAME",
            string("BTC Verifier Token")
        );
        string memory symbol_ = vm.envOr("TOKEN_SYMBOL", string("BVT"));

        vm.startBroadcast(pk);

        token = new BtcVerifierToken(
            checkpointHash,
            checkpointHeight,
            name_,
            symbol_,
            targetPKH
        );
        console2.log("Deployed at:", address(token));
        console2.log("oracle:", token.oracle());
        console2.log("TARGET_PKH pseudo-recipient:", _pkhToAddress(targetPKH));

        // ----- Optional: submit header -----
        string memory headerPath = vm.envOr("HEADER_HEX_PATH", string(""));
        if (bytes(headerPath).length != 0) {
            bytes memory header = _readHexFixture(headerPath);
            console2.log("Submitting header bytes length:", header.length);

            bool ok = token.oracleSubmitBlockHeader(header);
            console2.log("oracleSubmitBlockHeader ok:", ok);

            bytes32 canonical = BTCUtils.reverseBytes32(
                BTCUtils.sha256d(header)
            );
            console2.log("Submitted canonical block hash:");
            console2.logBytes32(canonical);
            console2.log("Known after submit:", token.isKnown(canonical));
            console2.log("Height:", token.getBlockHeight(canonical));
        }

        // ----- Optional: verify tx -----
        string memory txPath = vm.envOr("TX_HEX_PATH", string(""));
        string memory proofPath = vm.envOr("PROOF_JSON_PATH", string(""));
        if (bytes(txPath).length != 0) {
            require(bytes(proofPath).length != 0, "PROOF_JSON_PATH missing");

            bytes memory txBytes = _readHexFixture(txPath);
            bytes32[] memory proof = _readProofFromJson(proofPath);

            uint256 txIndex = vm.envUint("TX_INDEX");
            bytes32 blockHash = vm.envBytes32("BLOCK_HASH");

            console2.log("Verifying tx bytes length:", txBytes.length);
            console2.log("Proof length:", proof.length);

            bool ok2 = token.verifyTransaction(
                txBytes,
                proof,
                txIndex,
                blockHash
            );
            console2.log("verifyTransaction ok:", ok2);
        }

        vm.stopBroadcast();
    }
}
