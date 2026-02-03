#!/usr/bin/env python3
import json, os, sys, time, hashlib
from urllib.request import urlopen, Request

API_BASE = "https://blockstream.info/api"  # esplora-compatible APIs support /tx/:txid/hex and /tx/:txid/merkle-proof :contentReference[oaicite:0]{index=0}

FIX_DIR = "test/fixtures"
HEADER_PATH = os.path.join(FIX_DIR, "sample_header.hex")
TX_PATH = os.path.join(FIX_DIR, "sample_tx.hex")
PROOF_PATH = os.path.join(FIX_DIR, "sample_proof.json")

import subprocess

def http_get_text(url: str) -> str:
    # Use curl because it uses macOS system cert store (avoids Python SSL issues)
    return subprocess.check_output(["curl", "-sL", url], text=True)


def http_get_json(url: str):
    return json.loads(http_get_text(url))

def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def rev32(hexstr: str) -> str:
    # hexstr may include "0x"
    hs = hexstr[2:] if hexstr.startswith("0x") else hexstr
    return bytes.fromhex(hs)[::-1].hex()

def read_varint(b: bytes, p: int):
    fb = b[p]
    if fb < 0xfd:
        return fb, 1
    if fb == 0xfd:
        return int.from_bytes(b[p+1:p+3], "little"), 3
    if fb == 0xfe:
        return int.from_bytes(b[p+1:p+5], "little"), 5
    return int.from_bytes(b[p+1:p+9], "little"), 9

def parse_tx_outputs(tx_bytes: bytes):
    """
    Minimal parser to locate vout count and output0 (value, scriptPubKey).
    Handles segwit marker/flag for structure (NOT txid computation).
    """
    if len(tx_bytes) < 10:
        return None

    p = 0
    p += 4  # version

    # segwit marker+flag
    if len(tx_bytes) >= 6 and tx_bytes[4] == 0x00 and tx_bytes[5] == 0x01:
        p += 2

    vin_cnt, sz = read_varint(tx_bytes, p); p += sz

    # skip inputs
    for _ in range(vin_cnt):
        if p + 36 > len(tx_bytes): return None
        p += 36
        script_len, sz = read_varint(tx_bytes, p); p += sz
        if p + script_len + 4 > len(tx_bytes): return None
        p += script_len + 4  # scriptSig + sequence

    vout_cnt, sz = read_varint(tx_bytes, p); p += sz
    outs = []
    for _ in range(vout_cnt):
        if p + 8 > len(tx_bytes): return None
        value = int.from_bytes(tx_bytes[p:p+8], "little"); p += 8
        pk_len, sz = read_varint(tx_bytes, p); p += sz
        if p + pk_len > len(tx_bytes): return None
        script = tx_bytes[p:p+pk_len]; p += pk_len
        outs.append((value, script))

    return (vout_cnt, outs)

def is_p2pkh(script: bytes) -> bool:
    return (
        len(script) == 25 and
        script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14 and
        script[23] == 0x88 and script[24] == 0xac
    )

def is_p2pk(script: bytes) -> bool:
    return (
        (len(script) == 35 and script[0] == 0x21 and script[-1] == 0xac) or
        (len(script) == 67 and script[0] == 0x41 and script[-1] == 0xac)
    )

def hash160(pubkey: bytes) -> bytes:
    sha = hashlib.sha256(pubkey).digest()
    ripe = hashlib.new("ripemd160")
    ripe.update(sha)
    return ripe.digest()

def compute_blockhash_from_header_hex(header_hex: str) -> str:
    header = bytes.fromhex(header_hex)
    bh = sha256d(header)[::-1].hex()  # explorer/canonical style
    return "0x" + bh

def main():
    os.makedirs(FIX_DIR, exist_ok=True)

    header_hex = open(HEADER_PATH, "r", encoding="utf-8").read().strip()
    if header_hex.startswith("0x"): header_hex = header_hex[2:]
    if len(header_hex) != 160:
        print(f"[!] sample_header.hex should be 160 hex chars (80 bytes). Got len={len(header_hex)}")
        sys.exit(1)

    block_hash = compute_blockhash_from_header_hex(header_hex)
    print("[*] Block hash (canonical/explorer style):", block_hash)

    # 1) Get txids for the block
    txids_url = f"{API_BASE}/block/{block_hash[2:]}/txids"
    txids = http_get_json(txids_url)
    print(f"[*] Block tx count: {len(txids)}")

    # 2) Scan until we find a tx with exactly 2 outputs and output0 is P2PKH or P2PK
    chosen = None
    for i, txid in enumerate(txids):
        hex_url = f"{API_BASE}/tx/{txid}/hex"
        tx_hex = http_get_text(hex_url).strip()
        tx_bytes = bytes.fromhex(tx_hex)

        parsed = parse_tx_outputs(tx_bytes)
        if not parsed:
            continue
        vout_cnt, outs = parsed
        if vout_cnt != 2:
            continue

        value0, script0 = outs[0]

        if is_p2pkh(script0):
            pkh = script0[3:23]
            kind = "p2pkh"
        elif is_p2pk(script0):
            pub = script0[1:-1]
            pkh = hash160(pub)
            kind = "p2pk"
        else:
            continue

        chosen = {
            "txid": txid,
            "tx_hex": tx_hex,
            "valueSats": value0,
            "pkh": pkh.hex(),
            "kind": kind,
        }
        print(f"[*] Found candidate tx at block index guess {i}: {txid} ({kind}, value0={value0})")
        break

        # (optional throttle)
        # time.sleep(0.05)

    if not chosen:
        print("[!] Could not find a tx in this block with exactly 2 outputs and output0 P2PKH/P2PK.")
        print("    Options: (a) change sample_header.hex to a different block, or (b) loosen the output-count rule for integration.")
        sys.exit(1)

    # 3) Fetch merkle-proof for that tx
    mp_url = f"{API_BASE}/tx/{chosen['txid']}/merkle-proof"
    mp = http_get_json(mp_url)

    # mp is Electrum-style: { "block_height": n, "merkle": [..], "pos": idx }
    tx_index = mp["pos"]
    merkle = mp["merkle"]

    # Convert proof nodes from explorer-style hex to "raw digest bytes32" expected by your solidity verifier:
    # explorer gives big-endian; your contract works with the opposite (raw bytes32 used in hashing in your system),
    # so reverse each 32-byte element.
    proof = ["0x" + rev32(h) for h in merkle]

    expected_pkh = "0x" + chosen["pkh"]  # 20 bytes
    recipient = expected_pkh  # because your contract mints to address(bytes20(pkh))

    out = {
        "blockHash": block_hash,
        "txIndex": int(tx_index),
        "proof": proof,
        "expectedPKH": expected_pkh,
        "recipient": recipient,
        "valueSats": int(chosen["valueSats"]),
        "txid": chosen["txid"],
        "scriptType": chosen["kind"],
        "api": API_BASE
    }

    # 4) Write fixtures
    open(TX_PATH, "w", encoding="utf-8").write(chosen["tx_hex"] + "\n")
    open(PROOF_PATH, "w", encoding="utf-8").write(json.dumps(out, indent=2) + "\n")

    print("[+] Wrote:", TX_PATH)
    print("[+] Wrote:", PROOF_PATH)
    print("[+] expectedPKH / recipient:", expected_pkh)
    print("[+] txIndex:", tx_index)

if __name__ == "__main__":
    main()
