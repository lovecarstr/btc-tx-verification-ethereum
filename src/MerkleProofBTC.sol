// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BTCUtils} from "./BTCUtils.sol";

/// @title MerkleProofBTC
/// @notice Verifies Bitcoin-style Merkle proofs (double-SHA256 parent hashing).
/// @dev Expects `leaf`, each `proof[i]`, and `root` to be 32-byte digests in the SAME byte order
///      used for hashing (digest bytes). Do NOT pass explorer “display” hex unless you’ve
///      converted it consistently beforehand.
contract MerkleProofBTC {
    /// @notice Verify that `leaf` is included in the Merkle tree with `root`.
    /// @param proof Sibling hashes from leaf level up to root (bottom-up).
    /// @param root Merkle root to verify against.
    /// @param leaf Leaf hash (txid = sha256d(rawTx)).
    /// @param index Leaf position in the tree (used for left/right ordering).
    function verifyMerkleProof(bytes32[] memory proof, bytes32 root, bytes32 leaf, uint256 index)
        public
        pure
        returns (bool)
    {
        // 1-leaf tree case
        if (proof.length == 0) {
            return (index == 0) && (leaf == root);
        }

        bytes32 computed = leaf;
        uint256 idx = index;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 sibling = proof[i];

            if ((idx & 1) == 0) {
                // computed is left child
                computed = BTCUtils.sha256d(abi.encodePacked(computed, sibling));
            } else {
                // computed is right child
                computed = BTCUtils.sha256d(abi.encodePacked(sibling, computed));
            }

            idx >>= 1;
        }

        // Sanity guard: index shouldn’t have bits above proof depth.
        // Prevents index= (validIndex + k*2^proofLen) from accidentally passing.
        if (idx != 0) return false;

        return computed == root;
    }
}
