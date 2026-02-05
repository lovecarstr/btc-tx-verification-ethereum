// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {BtcVerifierToken} from "../src/BtcVerifierToken.sol";
import {BTCUtils} from "../src/BTCUtils.sol";

contract BtcVerifierTokenTask4Harness is BtcVerifierToken {
    constructor(
        bytes20 targetPKH
    )
        BtcVerifierToken(
            bytes32(uint256(1)),
            100,
            "BTC Verifier Token",
            "BVT",
            targetPKH
        )
    {}

    function setKnownBlockForTest(
        bytes32 blockHash,
        uint256 height,
        bytes32 merkleRootLE
    ) external {
        _setKnownBlockForTest(blockHash, height, merkleRootLE);
    }

    function mintBalance(address a) external view returns (uint256) {
        return balanceOf(a);
    }
}

contract VerifyTransactionTest is Test {
    BtcVerifierTokenTask4Harness token;

    bytes32 constant BLOCK = bytes32(uint256(0xB10C)); // arbitrary canonical block hash for tests

    // State variables can't be "memory"
    bytes pubkey33;
    bytes20 targetPKH;
    bytes32[] proof; // Declare proof variable

    function setUp() public {
        pubkey33 = new bytes(33);
        pubkey33[0] = 0x02;
        for (uint256 i = 1; i < 33; i++) {
            pubkey33[i] = bytes1(uint8(i));
        }

        targetPKH = _hash160(pubkey33);
        token = new BtcVerifierTokenTask4Harness(targetPKH);
        proof = new bytes32[](0); // Initialize proof as an empty array
    }

    // ---------- Helpers to build synthetic tx bytes ----------

    function _p2pkhScript(bytes20 pkh) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"76a914", pkh, hex"88ac");
    }

    function _u64le(uint64 v) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                bytes1(uint8(v)),
                bytes1(uint8(v >> 8)),
                bytes1(uint8(v >> 16)),
                bytes1(uint8(v >> 24)),
                bytes1(uint8(v >> 32)),
                bytes1(uint8(v >> 40)),
                bytes1(uint8(v >> 48)),
                bytes1(uint8(v >> 56))
            );
    }

    function _buildLegacyTx_2out_P2PKH(
        uint64 v0,
        bytes20 pkh0,
        uint64 v1,
        bytes20 pkh1
    ) internal pure returns (bytes memory) {
        bytes memory version = hex"01000000";
        bytes memory vinCount = hex"01";
        bytes memory input0 = abi.encodePacked(
            new bytes(32),
            hex"00000000",
            hex"00",
            hex"ffffffff"
        );
        bytes memory voutCount = hex"02";

        bytes memory script0 = _p2pkhScript(pkh0);
        bytes memory out0 = abi.encodePacked(
            _u64le(v0),
            bytes1(uint8(script0.length)),
            script0
        );

        bytes memory script1 = _p2pkhScript(pkh1);
        bytes memory out1 = abi.encodePacked(
            _u64le(v1),
            bytes1(uint8(script1.length)),
            script1
        );

        bytes memory locktime = hex"00000000";
        return
            abi.encodePacked(
                version,
                vinCount,
                input0,
                voutCount,
                out0,
                out1,
                locktime
            );
    }

    function _buildLegacyTx_badOutputsCount(
        uint64 v0,
        bytes20 pkh0
    ) internal pure returns (bytes memory) {
        bytes memory version = hex"01000000";
        bytes memory vinCount = hex"01";
        bytes memory input0 = abi.encodePacked(
            new bytes(32),
            hex"00000000",
            hex"00",
            hex"ffffffff"
        );

        bytes memory voutCount = hex"01"; // bad
        bytes memory script0 = _p2pkhScript(pkh0);
        bytes memory out0 = abi.encodePacked(
            _u64le(v0),
            bytes1(uint8(script0.length)),
            script0
        );
        bytes memory locktime = hex"00000000";

        return
            abi.encodePacked(
                version,
                vinCount,
                input0,
                voutCount,
                out0,
                locktime
            );
    }

    function _buildLegacyTx_badScript(
        uint64 v0
    ) internal pure returns (bytes memory) {
        bytes memory version = hex"01000000";
        bytes memory vinCount = hex"01";
        bytes memory input0 = abi.encodePacked(
            new bytes(32),
            hex"00000000",
            hex"00",
            hex"ffffffff"
        );

        bytes memory voutCount = hex"02";

        bytes memory badScript = hex"6a01ff"; // OP_RETURN push 1 byte ff
        bytes memory out0 = abi.encodePacked(
            _u64le(v0),
            bytes1(uint8(badScript.length)),
            badScript
        );

        bytes20 pkh1 = bytes20(uint160(0x1234));
        bytes memory script1 = _p2pkhScript(pkh1);
        bytes memory out1 = abi.encodePacked(
            _u64le(1),
            bytes1(uint8(script1.length)),
            script1
        );

        bytes memory locktime = hex"00000000";
        return
            abi.encodePacked(
                version,
                vinCount,
                input0,
                voutCount,
                out0,
                out1,
                locktime
            );
    }

    function _hash160(bytes memory pubkey) internal pure returns (bytes20) {
        bytes32 s = sha256(pubkey);
        return ripemd160(abi.encodePacked(s));
    }

    function _buildLegacyTx_2out_P2PK(
        uint64 v0,
        bytes memory pubkey,
        uint64 v1,
        bytes20 pkh1
    ) internal pure returns (bytes memory) {
        require(pubkey.length == 33 || pubkey.length == 65, "pubkey len");
        bytes1 len = bytes1(uint8(pubkey.length));
        bytes memory script0 = abi.encodePacked(len, pubkey, bytes1(0xac));

        bytes memory version = hex"01000000";
        bytes memory vinCount = hex"01";
        bytes memory input0 = abi.encodePacked(
            new bytes(32),
            hex"00000000",
            hex"00",
            hex"ffffffff"
        );
        bytes memory voutCount = hex"02";

        bytes memory out0 = abi.encodePacked(
            _u64le(v0),
            bytes1(uint8(script0.length)),
            script0
        );

        bytes memory script1 = _p2pkhScript(pkh1);
        bytes memory out1 = abi.encodePacked(
            _u64le(v1),
            bytes1(uint8(script1.length)),
            script1
        );

        bytes memory locktime = hex"00000000";
        return
            abi.encodePacked(
                version,
                vinCount,
                input0,
                voutCount,
                out0,
                out1,
                locktime
            );
    }

    function _buildSegwitTx_2out_P2PKH_withDummyWitness(
        uint64 v0,
        bytes20 pkh0,
        uint64 v1,
        bytes20 pkh1
    ) internal pure returns (bytes memory) {
        bytes memory version = hex"02000000";
        bytes memory mf = hex"0001";
        bytes memory vinCount = hex"01";
        bytes memory input0 = abi.encodePacked(
            new bytes(32),
            hex"00000000",
            hex"00",
            hex"ffffffff"
        );

        bytes memory voutCount = hex"02";

        bytes memory script0 = _p2pkhScript(pkh0);
        bytes memory out0 = abi.encodePacked(
            _u64le(v0),
            bytes1(uint8(script0.length)),
            script0
        );

        bytes memory script1 = _p2pkhScript(pkh1);
        bytes memory out1 = abi.encodePacked(
            _u64le(v1),
            bytes1(uint8(script1.length)),
            script1
        );

        bytes memory witness = hex"010101";
        bytes memory locktime = hex"00000000";

        return
            abi.encodePacked(
                version,
                mf,
                vinCount,
                input0,
                voutCount,
                out0,
                out1,
                witness,
                locktime
            );
    }

    function _pkhToAddress(bytes20 pkh) internal pure returns (address) {
        uint256 x = uint256(bytes32(pkh)) >> 96;
        return address(uint160(x));
    }

    function _slice(
        bytes memory data,
        uint256 start,
        uint256 length
    ) internal pure returns (bytes memory) {
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = data[start + i];
        }
        return result;
    }

    // ---------- Tests ----------

    function test_verifyTransaction_legacy_emptyProof_mints_and_marksValidated()
        public
    {
        bytes20 pkh1 = bytes20(uint160(0xBBBB));
        bytes memory txBytes = _buildLegacyTx_2out_P2PKH(
            1000,
            targetPKH,
            1,
            pkh1
        );

        bytes32 txid = BTCUtils.sha256d(txBytes);
        token.setKnownBlockForTest(BLOCK, 123, txid);

        // Initialize proof for the test (this should be the actual proof if applicable)
        proof = new bytes32[](0); // You may need to calculate the actual proof

        bool ok = token.verifyTransaction(txBytes, proof, 0, BLOCK);
        assertTrue(ok);

        address pseudo = _pkhToAddress(targetPKH);
        assertEq(token.mintBalance(pseudo), 1000);
        assertTrue(token.validatedTx(txid));
    }

    function test_verifyTransaction_enforces_target_recipient() public {
        bytes20 wrongPKH = bytes20(uint160(0xAAAA));
        require(wrongPKH != targetPKH, "choose different");

        bytes20 pkh1 = bytes20(uint160(0xBBBB));
        bytes memory txBytes = _buildLegacyTx_2out_P2PKH(
            100,
            wrongPKH,
            1,
            pkh1
        );

        bytes32 txid = BTCUtils.sha256d(txBytes);
        token.setKnownBlockForTest(BLOCK, 1, txid);

        // Initialize proof for the test
        proof = new bytes32[](0); // You may need to calculate the actual proof

        vm.expectRevert("wrong recipient");
        token.verifyTransaction(txBytes, proof, 0, BLOCK);
    }

    function test_verifyTransaction_doubleValidate_reverts() public {
        bytes20 pkh1 = bytes20(uint160(0x2222));
        bytes memory txBytes = _buildLegacyTx_2out_P2PKH(5, targetPKH, 1, pkh1);

        bytes32 txid = BTCUtils.sha256d(txBytes);
        token.setKnownBlockForTest(BLOCK, 1, txid);

        // Initialize proof for the test
        proof = new bytes32[](0); // You may need to calculate the actual proof

        assertTrue(token.verifyTransaction(txBytes, proof, 0, BLOCK));
        vm.expectRevert("tx already validated");
        token.verifyTransaction(txBytes, proof, 0, BLOCK);
    }

    function test_verifyTransaction_unknownBlock_reverts() public {
        bytes20 pkh1 = bytes20(uint160(0x4444));
        bytes memory txBytes = _buildLegacyTx_2out_P2PKH(5, targetPKH, 1, pkh1);

        // Initialize proof for the test
        proof = new bytes32[](0); // You may need to calculate the actual proof

        vm.expectRevert("unknown block");
        token.verifyTransaction(txBytes, proof, 0, BLOCK);
    }

    function test_verifyTransaction_badIndex_reverts() public {
        bytes20 pkh1 = bytes20(uint160(0x6666));
        bytes memory txBytes = _buildLegacyTx_2out_P2PKH(5, targetPKH, 1, pkh1);

        bytes32 txid = BTCUtils.sha256d(txBytes);
        token.setKnownBlockForTest(BLOCK, 1, txid);

        // Initialize proof for the test
        proof = new bytes32[](0); // You may need to calculate the actual proof

        vm.expectRevert("bad merkle proof");
        token.verifyTransaction(txBytes, proof, 7, BLOCK);
    }

    function test_verifyTransaction_wrongMerkleRoot_reverts() public {
        bytes20 pkh1 = bytes20(uint160(0x8888));
        bytes memory txBytes = _buildLegacyTx_2out_P2PKH(5, targetPKH, 1, pkh1);

        token.setKnownBlockForTest(BLOCK, 1, bytes32(uint256(0xDEAD)));

        // Initialize proof for the test
        proof = new bytes32[](0); // You may need to calculate the actual proof

        vm.expectRevert("bad merkle proof");
        token.verifyTransaction(txBytes, proof, 0, BLOCK);
    }

    function test_verifyTransaction_requires_2_outputs_reverts() public {
        bytes memory txBytes = _buildLegacyTx_badOutputsCount(5, targetPKH);

        bytes32 txid = BTCUtils.sha256d(txBytes);
        token.setKnownBlockForTest(BLOCK, 1, txid);

        // Initialize proof for the test
        proof = new bytes32[](0); // You may need to calculate the actual proof

        vm.expectRevert("tx must have 2 outputs");
        token.verifyTransaction(txBytes, proof, 0, BLOCK);
    }

    function test_verifyTransaction_rejects_non_p2pkh_p2pk() public {
        bytes memory txBytes = _buildLegacyTx_badScript(5);

        bytes32 txid = BTCUtils.sha256d(txBytes);
        token.setKnownBlockForTest(BLOCK, 1, txid);

        // Initialize proof for the test
        proof = new bytes32[](0); // You may need to calculate the actual proof

        vm.expectRevert("output0 not p2pkh/p2pk");
        token.verifyTransaction(txBytes, proof, 0, BLOCK);
    }

    function test_verifyTransaction_p2pk_extracts_hash160_and_mints_when_matches_target()
        public
    {
        bytes20 pkh1 = bytes20(uint160(0xABCD));
        bytes memory txBytes = _buildLegacyTx_2out_P2PK(42, pubkey33, 1, pkh1);

        bytes32 txid = BTCUtils.sha256d(txBytes);
        token.setKnownBlockForTest(BLOCK, 1, txid);

        // Initialize proof for the test
        proof = new bytes32[](0); // You may need to calculate the actual proof

        assertTrue(token.verifyTransaction(txBytes, proof, 0, BLOCK));

        address pseudo = _pkhToAddress(targetPKH);
        assertEq(token.mintBalance(pseudo), 42);
    }

    function test_verifyTransaction_segwit_txid_strips_witness_and_works()
        public
    {
        bytes20 pkh1 = bytes20(uint160(0xBBBB));
        bytes memory txBytes = _buildSegwitTx_2out_P2PKH_withDummyWitness(
            7,
            targetPKH,
            1,
            pkh1
        );

        bytes memory version = _slice(txBytes, 0, 4);

        uint256 afterOutputs = 117;
        bytes memory base = _slice(txBytes, 6, afterOutputs - 6);
        bytes memory locktime = _slice(txBytes, txBytes.length - 4, 4);

        bytes memory stripped = bytes.concat(version, base, locktime);
        bytes32 txid = BTCUtils.sha256d(stripped);

        token.setKnownBlockForTest(BLOCK, 1, txid);

        // Initialize proof for the test
        proof = new bytes32[](0); // You may need to calculate the actual proof

        assertTrue(token.verifyTransaction(txBytes, proof, 0, BLOCK));

        address pseudo = _pkhToAddress(targetPKH);
        assertEq(token.mintBalance(pseudo), 7);
    }
}
