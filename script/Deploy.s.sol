// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {BtcVerifierToken} from "../src/BtcVerifierToken.sol";

contract Deploy is Script {
    // Parse a hex string (0x...) into bytes20.
    // Accepts:
    // - 20-byte hex: 0x + 40 hex chars
    // - 32-byte hex: 0x + 64 hex chars (uses the LAST 20 bytes)
    function _envBytes20(string memory key) internal view returns (bytes20 out) {
        string memory s = vm.envString(key);

        bytes memory b = bytes(s);
        require(b.length >= 2 && b[0] == "0" && (b[1] == "x" || b[1] == "X"), "env must be 0x-prefixed");

        // Case A: exactly 20 bytes provided
        if (b.length == 42) {
            bytes memory parsed = vm.parseBytes(s); // should be 20 bytes
            require(parsed.length == 20, "env must decode to 20 bytes");
            assembly {
                out := mload(add(parsed, 0x20))
            }
            return out;
        }

        // Case B: 32 bytes provided -> take last 20 bytes
        if (b.length == 66) {
            bytes32 v = vm.parseBytes32(s);
            return bytes20(v); // low 20 bytes
        }

        revert("env length must be 42 (bytes20) or 66 (bytes32)");
    }

    // For display only: convert bytes20 -> pseudo-address (same logic as contract)
    function _pkhToAddress(bytes20 pkh) internal pure returns (address) {
        return address(uint160(uint256(bytes32(pkh)) >> 96));
    }

    function run() external returns (BtcVerifierToken token) {
        uint256 pk = vm.envUint("PRIVATE_KEY");

        bytes32 checkpointHash = vm.envBytes32("CHECKPOINT_HASH");
        uint256 checkpointHeight = vm.envUint("CHECKPOINT_HEIGHT");

        bytes20 targetPKH = _envBytes20("TARGET_PKH");

        string memory name_ = vm.envOr("TOKEN_NAME", string("BTC Verifier Token"));
        string memory symbol_ = vm.envOr("TOKEN_SYMBOL", string("BVT"));

        vm.startBroadcast(pk);
        token = new BtcVerifierToken(checkpointHash, checkpointHeight, name_, symbol_, targetPKH);
        vm.stopBroadcast();

        console2.log("BtcVerifierToken deployed at:", address(token));
        console2.log("oracle:", token.oracle());
        console2.log("checkpointHeight:", checkpointHeight);
        console2.log("checkpointHash:");
        console2.logBytes32(checkpointHash);

        console2.log("TARGET_PKH (bytes20):");
        console2.logBytes20(targetPKH);

        console2.log("TARGET_PKH pseudo-recipient (address):");
        console2.logAddress(_pkhToAddress(targetPKH));
    }
}
