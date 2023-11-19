import argparse
import json

import os

import logging
import shlex
import traceback

from dotenv import load_dotenv

from prompt_toolkit import prompt
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import FileHistory

from matt.btctools.auth_proxy import AuthServiceProxy

from matt.btctools import key
from matt.btctools.messages import CTransaction, CTxIn, CTxOut, sha256
from matt.btctools.segwit_addr import decode_segwit_address
from matt.environment import Environment
from matt import ContractInstance, ContractInstanceStatus, ContractManager
from matt.utils import print_tx
from matt.merkle import MerkleTree

from ram_contracts import RAM

logging.basicConfig(filename='matt-cli.log', level=logging.DEBUG)


class ActionArgumentCompleter(Completer):
    ACTION_ARGUMENTS = {
        "fund": ["amount="],
        "list": [],
        "printall": [],
        "withdraw": ["item=", "leaf_index=", "outputs=\"["],
        "write": ["item=", "leaf_index=", "new_value="],
    }

    def get_completions(self, document, complete_event):
        word_before_cursor = document.get_word_before_cursor(WORD=True)

        if ' ' not in document.text:
            # user is typing the action
            for action in self.ACTION_ARGUMENTS.keys():
                if action.startswith(word_before_cursor):
                    yield Completion(action, start_position=-len(word_before_cursor))
        else:
            # user is typing an argument, find which are valid
            action = document.text.split()[0]
            for argument in self.ACTION_ARGUMENTS.get(action, []):
                if argument not in document.text and argument.startswith(word_before_cursor):
                    yield Completion(argument, start_position=-len(word_before_cursor))


# point with provably unknown private key
NUMS_KEY: bytes = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

load_dotenv()

rpc_user = os.getenv("RPC_USER", "rpcuser")
rpc_password = os.getenv("RPC_PASSWORD", "rpcpass")
rpc_host = os.getenv("RPC_HOST", "localhost")
rpc_port = os.getenv("RPC_PORT", 18443)


def segwit_addr_to_scriptpubkey(addr: str) -> bytes:
    wit_ver, wit_prog = decode_segwit_address("bcrt", addr)

    if wit_ver is None or wit_prog is None:
        raise ValueError(f"Invalid segwit address (or wrong network): {addr}")

    return bytes([
        wit_ver + (0x50 if wit_ver > 0 else 0),
        len(wit_prog),
        *wit_prog
    ])


def parse_outputs(output_strings: list[str]) -> list[tuple[str, int]]:
    """Parses a list of strings in the form "address:amount" into a list of (address, amount) tuples.
    
    Args:
    - output_strings (list of str): List of strings in the form "address:amount".
    
    Returns:
    - list of (str, int): List of (address, amount) tuples.
    """
    outputs = []
    for output_str in output_strings:
        address, amount_str = output_str.split(":")
        amount = int(amount_str)
        if amount <= 0:
            raise ValueError(f"Invalid amount for address {address}: {amount_str}")
        outputs.append((address, amount))
    return outputs


def execute_command(input_line: str):
    # consider lines starting with '#' (possibly prefixed with whitespaces) as comments
    if input_line.strip().startswith("#"):
        return

    # Split into a command and the list of arguments
    try:
        input_line_list = shlex.split(input_line)
    except ValueError as e:
        print(f"Invalid command: {str(e)}")
        return

    # Ensure input_line_list is not empty
    if input_line_list:
        action = input_line_list[0].strip()
    else:
        return

    # Get the necessary arguments from input_command_list
    args_dict = {}
    pos_count = 0  # count of positional arguments
    for item in input_line_list[1:]:
        parts = item.strip().split('=', 1)
        if len(parts) == 2:
            param, value = parts
            args_dict[param] = value
        else:
            # record positional arguments with keys @0, @1, ...
            args_dict['@' + str(pos_count)] = parts[0]
            pos_count += 1

    if action == "":
        return
    elif action not in actions:
        print("Invalid action")
        return
    elif action == "list":
        for i, instance in enumerate(manager.instances):
            print(i, instance.status, instance)
    elif action == "mine":
        if '@0' in args_dict:
            n_blocks = int(args_dict['@0'])
        else:
            n_blocks = 1
        print(repr(manager._mine_blocks(n_blocks)))
    elif action == "printall":
        all_txs = {}
        for i, instance in enumerate(manager.instances):
            if instance.spending_tx is not None:
                all_txs[instance.spending_tx.hash] = (instance.contract.__class__.__name__, instance.spending_tx)

        for msg, tx in all_txs.values():
            print_tx(tx, msg)
    elif action == "withdraw":
        item_index = int(args_dict["item"])
        leaf_index = int(args_dict["leaf_index"])
        outputs = parse_outputs(json.loads(args_dict["outputs"]))

        if item_index not in range(len(manager.instances)):
            raise ValueError("Invalid item")

        R_inst = manager.instances[item_index]
        mt = MerkleTree(R_inst.data_expanded)

        if leaf_index not in range(len(R_inst.data_expanded)):
            raise ValueError("Invalid leaf index")

        args = {
            "merkle_root": mt.root,
            "merkle_proof": mt.prove_leaf(leaf_index)
        }

        spend_tx, _ = manager.get_spend_tx(
            (
                manager.instances[item_index],
                "withdraw",
                args
            )
        )

        # TODO: make utility function to create the vout easily
        spend_tx.vout = []
        for address, amount in outputs:
            spend_tx.vout.append(CTxOut(
                    nValue=amount,
                    scriptPubKey=segwit_addr_to_scriptpubkey(address)
                )
            )

        spend_tx.wit.vtxinwit = [manager.get_spend_wit(
            R_inst,
            "withdraw",
            args
        )]

        print(mt.prove_leaf(leaf_index))
        print(spend_tx)  # TODO: remove

        result = manager.spend_and_wait(R_inst, spend_tx)

        print("Done")
    elif action == "write":
        # TODO
        raise NotImplementedError
    elif action == "fund":
        amount = int(args_dict["amount"])
        R_inst = ContractInstance(R)
        R_inst.data_expanded = list(map(lambda x : sha256(x.to_bytes(1, byteorder='little')), range(R.size)))
        R_inst.data = MerkleTree(R_inst.data_expanded).root

        manager.add_instance(R_inst)
        txid = rpc.sendtoaddress(R_inst.get_address(), amount/100_000_000)
        print(f"Waiting for funding transaction {txid} to be confirmed...")
        manager.wait_for_outpoint(R_inst, txid)
        print(R_inst.funding_tx)


def cli_main():
    completer = ActionArgumentCompleter()
    # Create a history object
    history = FileHistory('.cli-history')

    while True:
        try:
            input_line = prompt("₿ ", history=history, completer=completer)
            execute_command(input_line)
        except (KeyboardInterrupt, EOFError):
            raise  # exit
        except Exception as err:
            print(f"Error: {err}")
            print(traceback.format_exc())


def script_main(script_filename: str):
    with open(script_filename, "r") as script_file:
        for input_line in script_file:
            try:
                # Assuming each command can be executed in a similar manner to the CLI
                # This will depend on the structure of the main() function and may need adjustments
                execute_command(input_line)
            except Exception as e:
                print(f"Error executing command: {input_line.strip()} - Error: {str(e)}")
                break


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Mine automatically option
    parser.add_argument("--mine-automatically", "-m", action="store_true", help="Mine automatically")

    # Script file option
    parser.add_argument("--script", "-s", type=str, help="Execute commands from script file")

    args = parser.parse_args()

    actions = ["fund", "mine", "list", "printall", "withdraw"]

    unvault_priv_key = key.ExtendedKey.deserialize(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN")
    recover_priv_key = key.ExtendedKey.deserialize(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ")

    rpc = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}")

    R = RAM(8)

    manager = ContractManager([], rpc, mine_automatically=args.mine_automatically)
    environment = Environment(rpc, manager, None, None, False)

    # map from known ctv hashes to the corresponding template (used for withdrawals)
    ctv_templates: dict[bytes, CTransaction] = {}


    if args.script:
        script_main(args.script)
    else:
        try:
            cli_main()
        except (KeyboardInterrupt, EOFError):
            pass  # exit
