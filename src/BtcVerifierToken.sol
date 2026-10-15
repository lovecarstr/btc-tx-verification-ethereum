// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BitcoinHeaderChain} from "./BitcoinHeaderChain.sol";
import {BTCUtils} from "./BTCUtils.sol";
import {MerkleProofBTC} from "./MerkleProofBTC.sol";

contract BtcVerifierToken is BitcoinHeaderChain, MerkleProofBTC {
    // ----------------
    // ERC-20 Metadata
    // ----------------
    string private _name;
    string private _symbol;
    uint8 private immutable _decimals;

    // ----------------
    // ERC-20 Storage
    // ----------------
    uint256 private _totalSupply;
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    // ----------------
    // Task 4 Storage
    // ----------------
    mapping(bytes32 => bool) public validatedTx; // txid (digest/internal order) -> used

    /// @notice The “specific Bitcoin address” requirement is enforced by storing its HASH160 (pubKeyHash).
    /// @dev For P2PKH: script includes this hash directly.
    ///      For P2PK: we hash160(pubkey) and compare to this.
    bytes20 public immutable TARGET_PKH;

    // ----------------
    // ERC-20 Events
    // ----------------
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // ----------------
    // Task 4 Events (nice-to-have)
    // ----------------
    event TransactionVerified(
        bytes32 indexed txid, bytes32 indexed blockHash, bytes20 indexed pubKeyHash, uint64 valueSats
    );

    // ----------------
    // Task 5: Oracle header posting helper
    // ----------------
    address public oracle;

    event OracleChanged(address indexed oldOracle, address indexed newOracle);

    modifier onlyOracle() {
        require(msg.sender == oracle, "not oracle");
        _;
    }

    constructor(
        bytes32 checkpointHash,
        uint256 checkpointHeight,
        string memory name_,
        string memory symbol_,
        bytes20 targetPKH_
    ) BitcoinHeaderChain(checkpointHash, checkpointHeight) {
        require(targetPKH_ != bytes20(0), "target pkh zero");

        _name = name_;
        _symbol = symbol_;
        _decimals = 8; // satoshi-like base unit
        _totalSupply = 0;

        TARGET_PKH = targetPKH_;

        oracle = msg.sender;
        emit OracleChanged(address(0), oracle);
    }

    // ----------------
    // ERC-20 Views
    // ----------------
    function name() external view returns (string memory) {
        return _name;
    }

    function symbol() external view returns (string memory) {
        return _symbol;
    }

    function decimals() external view returns (uint8) {
        return _decimals;
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address a) public view returns (uint256) {
        return _balances[a];
    }

    function allowance(address owner, address spender) external view returns (uint256) {
        return _allowances[owner][spender];
    }

    // ----------------
    // ERC-20 Core
    // ----------------
    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        require(spender != address(0), "approve to zero");
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(from != address(0), "from zero");
        require(to != address(0), "to zero");

        uint256 curr = _allowances[from][msg.sender];
        require(curr >= amount, "insufficient allowance");

        if (curr != type(uint256).max) {
            unchecked {
                _allowances[from][msg.sender] = curr - amount;
            }
            emit Approval(from, msg.sender, _allowances[from][msg.sender]);
        }

        _transfer(from, to, amount);
        return true;
    }

    function burn(uint256 amount) external returns (bool) {
        _burn(msg.sender, amount);
        return true;
    }

    function burnFrom(address from, uint256 amount) external returns (bool) {
        uint256 curr = _allowances[from][msg.sender];
        require(curr >= amount, "insufficient allowance");

        if (curr != type(uint256).max) {
            unchecked {
                _allowances[from][msg.sender] = curr - amount;
            }
            emit Approval(from, msg.sender, _allowances[from][msg.sender]);
        }

        _burn(from, amount);
        return true;
    }

    // ----------------
    // Task 4 (Required Interface)
    // ----------------

    /// @notice Prove `transaction` is included in `blockHash` and mint tokens to output0 recipient PKH.
    /// @dev Supports legacy and SegWit txid rules (SegWit txid excludes marker/flag + witness).
    ///      Enforces that output0 is to the specific Bitcoin address (TARGET_PKH), as required by spec.
    function verifyTransaction(
        bytes memory transaction,
        bytes32[] memory merkleProof,
        uint256 txIndex,
        bytes32 blockHash
    ) public returns (bool) {
        // 1) Validate block hash
        require(isKnown(blockHash), "unknown block");

        // 2) Merkle root for this block (stored from header submission)
        bytes32 merkleRootLE = getMerkleRoot(blockHash);

        // 3) Compute txid (digest/internal order) correctly (legacy vs segwit)
        bytes32 txid = _computeTxid(transaction);

        // 4) Verify Merkle proof
        bool ok = verifyMerkleProof(merkleProof, merkleRootLE, txid, txIndex);
        require(ok, "bad merkle proof");

        // 5) Prevent double validation
        require(!validatedTx[txid], "tx already validated");
        validatedTx[txid] = true;

        // 6) Parse tx and validate first output script (must be P2PKH or P2PK)
        (uint64 valueSats, bytes20 pubKeyHash) = _parseFirstOutputAndExtractPKH(transaction);

        // 7) Enforce “specific Bitcoin address” requirement (spec)
        require(pubKeyHash == TARGET_PKH, "wrong recipient");

        // 8) Mint ERC-20 tokens equal to satoshis to pseudo-address derived from PKH
        address pseudoRecipient = _pkhToAddress(pubKeyHash);
        _mint(pseudoRecipient, uint256(valueSats));

        emit TransactionVerified(txid, blockHash, pubKeyHash, valueSats);
        return true;
    }

    // ----------------
    // Task 5: Oracle helpers
    // ----------------

    /// @notice Task 5 workflow helper: oracle submits headers through this entrypoint.
    /// @dev This does NOT remove permissionless submission; it just makes the “oracle flow” explicit.
    function oracleSubmitBlockHeader(bytes calldata header) external onlyOracle returns (bool) {
        return submitBlockHeader(header);
    }

    /// @notice Change the oracle (admin = current oracle).
    function setOracle(address newOracle) external onlyOracle {
        require(newOracle != address(0), "oracle zero");
        emit OracleChanged(oracle, newOracle);
        oracle = newOracle;
    }

    // ----------------
    // Internal ERC-20 ops
    // ----------------
    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0), "transfer to zero");
        uint256 bal = _balances[from];
        require(bal >= amount, "insufficient balance");
        unchecked {
            _balances[from] = bal - amount;
            _balances[to] += amount;
        }
        emit Transfer(from, to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        require(to != address(0), "mint to zero");
        _totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        uint256 bal = _balances[from];
        require(bal >= amount, "insufficient balance");
        unchecked {
            _balances[from] = bal - amount;
            _totalSupply -= amount;
        }
        emit Transfer(from, address(0), amount);
    }

    // ----------------
    // TXID computation (legacy + segwit-safe)
    // ----------------
    function _computeTxid(bytes memory txBytes) internal pure returns (bytes32) {
        require(txBytes.length >= 10, "tx too short");

        // Legacy: txid = sha256d(full bytes)
        // SegWit: txid = sha256d(stripped serialization excluding marker/flag + witness)
        bool isSegwit = (txBytes.length >= 6 && txBytes[4] == 0x00 && txBytes[5] == 0x01);

        if (!isSegwit) {
            return BTCUtils.sha256d(txBytes);
        }

        // SegWit format:
        // version(4) | marker(1)=00 | flag(1)=01 | vinCount | inputs | voutCount | outputs | witness | locktime(4)

        uint256 p = 6; // after marker+flag
        (uint256 vinCount, uint256 vinSz) = _readVarIntMem(txBytes, p);
        p += vinSz;

        // Skip inputs
        for (uint256 i = 0; i < vinCount; i++) {
            require(p + 36 <= txBytes.length, "tx input oob");
            p += 36;

            (uint256 scriptLen, uint256 slSz) = _readVarIntMem(txBytes, p);
            p += slSz;

            require(p + scriptLen + 4 <= txBytes.length, "tx scriptsig oob");
            p += scriptLen;
            p += 4; // sequence
        }

        (uint256 voutCount, uint256 voutSz) = _readVarIntMem(txBytes, p);
        p += voutSz;

        // Skip outputs (we just need to know where outputs end)
        for (uint256 j = 0; j < voutCount; j++) {
            require(p + 8 <= txBytes.length, "tx out value oob");
            p += 8;

            (uint256 pkLen, uint256 pkSz) = _readVarIntMem(txBytes, p);
            p += pkSz;

            require(p + pkLen <= txBytes.length, "tx out script oob");
            p += pkLen;
        }

        uint256 afterOutputs = p;

        // Parse witness stacks for each input to locate locktime
        for (uint256 i2 = 0; i2 < vinCount; i2++) {
            (uint256 nItems, uint256 niSz) = _readVarIntMem(txBytes, p);
            p += niSz;

            for (uint256 k = 0; k < nItems; k++) {
                (uint256 itemLen, uint256 ilSz) = _readVarIntMem(txBytes, p);
                p += ilSz;
                require(p + itemLen <= txBytes.length, "witness oob");
                p += itemLen;
            }
        }

        // locktime must be present (last 4 bytes in real tx)
        require(p + 4 <= txBytes.length, "locktime oob");
        bytes memory locktime = _sliceMem(txBytes, p, 4);

        // Build stripped serialization: version + (vin..outputs) + locktime
        // That is: txBytes[0:4] + txBytes[6:afterOutputs] + locktime
        bytes memory version = _sliceMem(txBytes, 0, 4);
        bytes memory base = _sliceMem(txBytes, 6, afterOutputs - 6);

        bytes memory stripped = bytes.concat(version, base, locktime);
        return BTCUtils.sha256d(stripped);
    }

    // ----------------
    // Transaction parsing (enforce 2 outputs + extract output0 PKH)
    // ----------------
    function _parseFirstOutputAndExtractPKH(bytes memory txBytes)
        internal
        pure
        returns (uint64 valueSats, bytes20 pubKeyHash)
    {
        require(txBytes.length >= 10, "tx too short");

        uint256 p = 0;

        // version
        p += 4;

        // Detect segwit marker/flag and skip them for parsing structure
        if (txBytes.length >= 6 && txBytes[4] == 0x00 && txBytes[5] == 0x01) {
            p += 2; // marker+flag
        }

        (uint256 vinCount, uint256 vinSz) = _readVarIntMem(txBytes, p);
        p += vinSz;

        // skip inputs
        for (uint256 i = 0; i < vinCount; i++) {
            require(p + 36 <= txBytes.length, "tx input oob");
            p += 36;

            (uint256 scriptLen, uint256 slSz) = _readVarIntMem(txBytes, p);
            p += slSz;

            require(p + scriptLen + 4 <= txBytes.length, "tx scriptsig oob");
            p += scriptLen;
            p += 4; // sequence
        }

        (uint256 voutCount, uint256 voutSz) = _readVarIntMem(txBytes, p);
        p += voutSz;

        require(voutCount == 2, "tx must have 2 outputs");

        // Output 0: value(8) + pkScriptLen(varint) + pkScript
        require(p + 8 <= txBytes.length, "tx output0 value oob");
        valueSats = _readUint64LEMem(txBytes, p);
        p += 8;

        (uint256 pkLen, uint256 pkSz) = _readVarIntMem(txBytes, p);
        p += pkSz;

        require(p + pkLen <= txBytes.length, "tx output0 script oob");
        bytes memory script = _sliceMem(txBytes, p, pkLen);
        p += pkLen;

        if (_isP2PKH(script)) {
            pubKeyHash = _bytesToBytes20(script, 3); // bytes[3..22]
        } else if (_isP2PK(script)) {
            bytes memory pubkey = _sliceMem(script, 1, script.length - 2); // strip len byte + trailing OP_CHECKSIG
            pubKeyHash = _hash160(pubkey);
        } else {
            revert("output0 not p2pkh/p2pk");
        }

        // Output1 exists (change) by count; we don't validate it beyond structure.
    }

    function _isP2PKH(bytes memory s) internal pure returns (bool) {
        if (s.length != 25) return false;
        return (s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac);
    }

    function _isP2PK(bytes memory s) internal pure returns (bool) {
        // 21 <33 pubkey> ac  (len 35)
        if (s.length == 35 && s[0] == 0x21 && s[34] == 0xac) return true;
        // 41 <65 pubkey> ac  (len 67)
        if (s.length == 67 && s[0] == 0x41 && s[66] == 0xac) return true;
        return false;
    }

    function _hash160(bytes memory pubkey) internal pure returns (bytes20) {
        bytes32 sha = sha256(pubkey);
        return ripemd160(abi.encodePacked(sha));
    }

    function _pkhToAddress(bytes20 pkh) internal pure returns (address) {
        // bytes20 -> bytes32 is left-aligned; shift it down into the low 20 bytes
        return address(uint160(uint256(bytes32(pkh)) >> 96));
    }

    // ----------------
    // Minimal memory parsing helpers (canonical VarInt + LE uint64)
    // ----------------
    function _readVarIntMem(bytes memory b, uint256 p) internal pure returns (uint256 v, uint256 size) {
        require(p < b.length, "varint oob");
        uint8 fb = uint8(b[p]);

        if (fb < 0xfd) {
            return (fb, 1);
        } else if (fb == 0xfd) {
            require(p + 2 < b.length, "varint16 oob");
            uint256 vv = uint256(uint8(b[p + 1])) | (uint256(uint8(b[p + 2])) << 8);
            require(vv >= 0xfd, "varint non-canonical");
            return (vv, 3);
        } else if (fb == 0xfe) {
            require(p + 4 < b.length, "varint32 oob");
            uint256 vv = uint256(uint8(b[p + 1])) | (uint256(uint8(b[p + 2])) << 8) | (uint256(uint8(b[p + 3])) << 16)
                | (uint256(uint8(b[p + 4])) << 24);
            require(vv > 0xffff, "varint non-canonical");
            return (vv, 5);
        } else {
            require(p + 8 < b.length, "varint64 oob");
            v = 0;
            for (uint256 i = 0; i < 8; i++) {
                v |= uint256(uint8(b[p + 1 + i])) << (8 * i);
            }
            require(v > 0xffffffff, "varint non-canonical");
            return (v, 9);
        }
    }

    function _readUint64LEMem(bytes memory b, uint256 p) internal pure returns (uint64) {
        require(p + 8 <= b.length, "uint64 oob");
        uint64 v = 0;
        for (uint256 i = 0; i < 8; i++) {
            v |= uint64(uint8(b[p + i])) << uint64(8 * i);
        }
        return v;
    }

    function _sliceMem(bytes memory data, uint256 offset, uint256 len) internal pure returns (bytes memory out) {
        require(offset + len <= data.length, "slice oob");
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = data[offset + i];
        }
    }

    function _bytesToBytes20(bytes memory b, uint256 offset) internal pure returns (bytes20 out) {
        require(offset + 20 <= b.length, "bytes20 oob");
        assembly {
            // bytes20 values are LEFT-aligned in a 32-byte word.
            // mload(...) returns the first 20 bytes in the correct (high) position, so DO NOT shift.
            out := mload(add(add(b, 0x20), offset))
        }
    }
}
