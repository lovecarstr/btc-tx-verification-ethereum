// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MerkleProofBTC} from "../src/MerkleProofBTC.sol";

contract MerkleProofTest is Test {
    MerkleProofBTC mp;

    function setUp() public {
        mp = new MerkleProofBTC();
    }

    // Helper: Bitcoin-style parent hash = sha256d(left || right)
    function _sha256dPair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        bytes32 h1 = sha256(abi.encodePacked(left, right));
        return sha256(abi.encodePacked(h1));
    }

    function test_verifyMerkleProof_valid_evenIndex() public {
        bytes32 L0 = bytes32(uint256(0xA0));
        bytes32 L1 = bytes32(uint256(0xA1));
        bytes32 L2 = bytes32(uint256(0xA2));
        bytes32 L3 = bytes32(uint256(0xA3));

        bytes32 H01 = _sha256dPair(L0, L1);
        bytes32 H23 = _sha256dPair(L2, L3);
        bytes32 root = _sha256dPair(H01, H23);

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = L3;
        proof[1] = H01;

        assertTrue(mp.verifyMerkleProof(proof, root, L2, 2));
    }

    function test_verifyMerkleProof_valid_oddIndex() public {
        bytes32 L0 = bytes32(uint256(0xB0));
        bytes32 L1 = bytes32(uint256(0xB1));
        bytes32 L2 = bytes32(uint256(0xB2));
        bytes32 L3 = bytes32(uint256(0xB3));

        bytes32 H01 = _sha256dPair(L0, L1);
        bytes32 H23 = _sha256dPair(L2, L3);
        bytes32 root = _sha256dPair(H01, H23);

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = L2;
        proof[1] = H01;

        assertTrue(mp.verifyMerkleProof(proof, root, L3, 3));
    }

    function test_verifyMerkleProof_wrongIndex_fails() public {
        bytes32 L0 = bytes32(uint256(0xC0));
        bytes32 L1 = bytes32(uint256(0xC1));
        bytes32 L2 = bytes32(uint256(0xC2));
        bytes32 L3 = bytes32(uint256(0xC3));

        bytes32 H01 = _sha256dPair(L0, L1);
        bytes32 H23 = _sha256dPair(L2, L3);
        bytes32 root = _sha256dPair(H01, H23);

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = L3;
        proof[1] = H01;

        assertFalse(mp.verifyMerkleProof(proof, root, L2, 3));
    }

    function test_verifyMerkleProof_wrongRoot_fails() public {
        bytes32 L0 = bytes32(uint256(0xD0));
        bytes32 L1 = bytes32(uint256(0xD1));
        bytes32 L2 = bytes32(uint256(0xD2));
        bytes32 L3 = bytes32(uint256(0xD3));

        bytes32 H01 = _sha256dPair(L0, L1);
        bytes32 H23 = _sha256dPair(L2, L3);
        bytes32 root = _sha256dPair(H01, H23);

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = L3;
        proof[1] = H01;

        bytes32 badRoot = bytes32(uint256(root) ^ 1);
        assertFalse(mp.verifyMerkleProof(proof, badRoot, L2, 2));
    }

    function test_verifyMerkleProof_wrongProofElement_fails() public {
        bytes32 L0 = bytes32(uint256(0xE0));
        bytes32 L1 = bytes32(uint256(0xE1));
        bytes32 L2 = bytes32(uint256(0xE2));
        bytes32 L3 = bytes32(uint256(0xE3));

        bytes32 H01 = _sha256dPair(L0, L1);
        bytes32 H23 = _sha256dPair(L2, L3);
        bytes32 root = _sha256dPair(H01, H23);

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = bytes32(uint256(0xDEADBEEF));
        proof[1] = H01;

        assertFalse(mp.verifyMerkleProof(proof, root, L2, 2));
    }

    function test_verifyMerkleProof_emptyProof_leafEqualsRoot() public {
        bytes32 leaf = bytes32(uint256(123));
        bytes32[] memory proof = new bytes32[](0);

        assertTrue(mp.verifyMerkleProof(proof, leaf, leaf, 0));
    }

    function test_verifyMerkleProof_emptyProof_leafNotRoot() public {
        bytes32 leaf = bytes32(uint256(123));
        bytes32 root = bytes32(uint256(456));
        bytes32[] memory proof = new bytes32[](0);

        assertFalse(mp.verifyMerkleProof(proof, root, leaf, 0));
    }

    function test_verifyMerkleProof_oddDuplication_case() public {
        bytes32 L0 = bytes32(uint256(0x11));
        bytes32 L1 = bytes32(uint256(0x22));
        bytes32 L2 = bytes32(uint256(0x33));

        bytes32 H01 = _sha256dPair(L0, L1);
        bytes32 H22 = _sha256dPair(L2, L2);
        bytes32 root = _sha256dPair(H01, H22);

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = L2;
        proof[1] = H01;

        assertTrue(mp.verifyMerkleProof(proof, root, L2, 2));
    }

    function test_verifyMerkleProof_indexTooLargeForDepth_fails() public {
        bytes32 L0 = bytes32(uint256(0xF0));
        bytes32 L1 = bytes32(uint256(0xF1));
        bytes32 L2 = bytes32(uint256(0xF2));
        bytes32 L3 = bytes32(uint256(0xF3));

        bytes32 H01 = _sha256dPair(L0, L1);
        bytes32 H23 = _sha256dPair(L2, L3);
        bytes32 root = _sha256dPair(H01, H23);

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = L3;
        proof[1] = H01;

        assertFalse(mp.verifyMerkleProof(proof, root, L2, 6));
    }
}
