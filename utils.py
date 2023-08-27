from io import BytesIO
from typing import Optional, Tuple
from btctools.auth_proxy import AuthServiceProxy, JSONRPCException
import time

from btctools.messages import COutPoint, CTransaction


# We ignore the possibility of reorgs for simplicity.

def wait_for_output(
    rpc_connection: AuthServiceProxy,
    script_pub_key: bytes,
    poll_interval=1,
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


def wait_for_spending_tx(rpc_connection: AuthServiceProxy, outpoint: COutPoint, poll_interval=1, starting_height: Optional[int] = None) -> Tuple[CTransaction, int, int]:
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
