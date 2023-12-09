from io import BytesIO
from typing import Optional, Tuple
import time

from .btctools.auth_proxy import AuthServiceProxy, JSONRPCException
from .btctools.messages import COutPoint, CTransaction, CTxIn, CTxOut
from .btctools.script import CScript, CScriptNum, bn2vch
from .btctools.segwit_addr import decode_segwit_address


def vch2bn(s: bytes) -> int:
    """Convert bitcoin-specific little endian format to number."""
    if len(s) == 0:
        return 0
    # The most significant bit is the sign bit.
    is_negative = s[0] & 0x80 != 0
    # Mask off the sign bit.
    s_abs = bytes([s[0] & 0x7f]) + s[1:]
    v_abs = int.from_bytes(s_abs, 'little')
    # Return as negative number if it's negative.
    return -v_abs if is_negative else v_abs


def encode_wit_element(x: bytes | int) -> bytes:
    if isinstance(x, int):
        return bn2vch(x)
    elif isinstance(x, bytes):
        return x
    else:
        raise ValueError("Unexpected type")


# We ignore the possibility of reorgs for simplicity.

def wait_for_output(
    rpc_connection: AuthServiceProxy,
    script_pub_key: bytes,
    poll_interval: float = 1,
    starting_height: Optional[int] = None,
    txid: Optional[str] = None,
    min_amount: Optional[int] = None
) -> Tuple[COutPoint, int]:
    # Initialize the last block height using the provided starting_height or the current block height
    last_block_height = max(starting_height - 1, 0) if starting_height is not None else rpc_connection.getblockcount()

    while True:
        try:
            # Get the latest block height
            current_block_height = rpc_connection.getblockcount()

            if last_block_height > current_block_height:
                time.sleep(poll_interval)
                continue

            block_hash = rpc_connection.getblockhash(last_block_height)
            block = rpc_connection.getblock(block_hash, 2)

            # Check all transactions in the block
            for tx in block["tx"]:
                # If txid is provided, ensure the current transaction matches it
                if txid and tx["txid"] != txid:
                    continue

                # Check all outputs in the transaction
                for vout_index, vout in enumerate(tx["vout"]):
                    # Ensure the amount is above the min_amount if it is provided
                    if min_amount and vout["value"] < min_amount:
                        continue

                    if vout["scriptPubKey"]["hex"] == script_pub_key.hex():
                        return COutPoint(int(tx["txid"], 16), vout_index), last_block_height

            # Update the last block height
            last_block_height += 1

        except JSONRPCException as json_exception:
            print(f"A JSON RPC Exception occurred: {json_exception}")

        time.sleep(poll_interval)


def wait_for_spending_tx(rpc_connection: AuthServiceProxy, outpoint: COutPoint, poll_interval: float = 1, starting_height: Optional[int] = None) -> Tuple[CTransaction, int, int]:
    # Initialize the last block height using the provided starting_height or the current block height
    last_block_height = max(starting_height - 1, 0) if starting_height is not None else rpc_connection.getblockcount()

    while True:
        try:
            # Get the latest block height
            current_block_height = rpc_connection.getblockcount()

            if last_block_height > current_block_height:
                time.sleep(poll_interval)
                continue

            block_hash = rpc_connection.getblockhash(last_block_height)
            block = rpc_connection.getblock(block_hash, 2)

            for tx in block["tx"]:
                # Check all inputs in the transaction
                for vin_index, vin in enumerate(tx["vin"]):
                    if "txid" not in vin:
                        continue

                    txid = int(vin["txid"], 16)

                    if txid == outpoint.hash and vin["vout"] == outpoint.n:
                        result_tx = CTransaction()
                        result_tx.deserialize(BytesIO(bytes.fromhex(tx['hex'])))
                        return result_tx, vin_index, last_block_height

            last_block_height += 1

        except JSONRPCException as json_exception:
            print(f"A JSON RPC Exception occurred: {json_exception}")

        time.sleep(poll_interval)


# stolen from jamesob: https://github.com/bitcoin/bitcoin/pull/28550
def _pprint_tx(tx: CTransaction) -> str:
    s = f"CTransaction: (nVersion={tx.nVersion}, {int(len(tx.serialize().hex()) / 2)} bytes)\n"
    s += "  vin:\n"
    for i, inp in enumerate(tx.vin):
        s += f"    - [{i}] {inp}\n"
    s += "  vout:\n"
    for i, out in enumerate(tx.vout):
        s += f"    - [{i}] {out}\n"

    s += "  witnesses:\n"
    for i, wit in enumerate(tx.wit.vtxinwit):
        witbytes = sum(len(s) or 1 for s in wit.scriptWitness.stack)
        s += f"    - [{i}] ({witbytes} bytes, {witbytes / 4} vB)\n"
        for j, item in enumerate(wit.scriptWitness.stack):
            if type(item) is bytes:
                scriptstr = repr(CScript([item]))
            elif type(item) in {CScript, CScriptNum}:
                scriptstr = repr(item)
            else:
                raise NotImplementedError

            s += f"      - [{i}.{j}] ({len(item)} bytes) {scriptstr}\n"

    s += f"  nLockTime: {tx.nLockTime}\n"
    return s


# Utilities to print transactions
def print_tx(tx: CTransaction, title: str):
    print(
f'''
<details><summary>{title}<i>({tx.get_vsize()} vB)</i></summary>

```python
{_pprint_tx(tx)}
```

</details>

''')


def addr_to_script(addr: str) -> bytes:
    # only for segwit/taproot on regtest
    # TODO: generalize to other address types, and other networks (currently, it assumes regtest)

    wit_ver, wit_prog = decode_segwit_address("bcrt", addr)

    if wit_ver is None or wit_prog is None:
        raise ValueError(f"Invalid segwit address (or wrong network): {addr}")

    return bytes([
        wit_ver + (0x50 if wit_ver > 0 else 0),
        len(wit_prog),
        *wit_prog
    ])


def make_ctv_template(outputs: list[(bytes|str, int)], *, nVersion: int = 2, nSequence: int = 0) -> CTransaction:
    tmpl = CTransaction()
    tmpl.nVersion = nVersion
    tmpl.vin = [CTxIn(nSequence=nSequence)]
    for dest, amount in outputs:
        tmpl.vout.append(
            CTxOut(
                nValue=amount,
                scriptPubKey=dest if isinstance(dest, bytes) else addr_to_script(dest)
            )
        )
    return tmpl
