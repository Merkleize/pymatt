"""
Vaults similar to those described in https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2023-April/021588.html,
with several updates to implement the missing OP_VAULT features.
"""

import argparse
import json

import os

import logging
import shlex
import traceback
from typing import Dict, List, Tuple

from dotenv import load_dotenv

from prompt_toolkit import prompt
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import FileHistory

from matt.btctools.auth_proxy import AuthServiceProxy
from matt.btctools import key
from matt.btctools.messages import CTransaction, CTxIn, CTxOut
from matt.btctools.segwit_addr import decode_segwit_address
from matt.environment import Environment
from matt.manager import ContractInstance, ContractInstanceStatus, ContractManager
from matt.utils import format_tx_markdown

from vault_contracts import Unvaulting, Vault

logging.basicConfig(filename='matt-cli.log', level=logging.DEBUG)


class ActionArgumentCompleter(Completer):
    ACTION_ARGUMENTS = {
        "fund": ["amount="],
        "list": [],
        "printall": [],
        "recover": ["item="],
        "trigger": ["items=\"[", "outputs=\"["],
        "withdraw": ["item="],  # TODO: allow multiple items?
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


def parse_outputs(output_strings: List[str]) -> List[Tuple[str, int]]:
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
            print(format_tx_markdown(tx, msg))
    elif action == "trigger":
        items_idx = json.loads(args_dict["items"])
        print("Triggering: ", items_idx)

        if not isinstance(items_idx, list) or len(set(items_idx)) != len(items_idx):
            raise ValueError("Invalid items")

        spending_vaults: List[ContractInstance] = []
        for idx in items_idx:
            if idx >= len(manager.instances):
                raise ValueError(f"No such instance: {idx}")
            instance: ContractInstance = manager.instances[idx]
            if instance.status != ContractInstanceStatus.FUNDED:
                raise ValueError("Only FUNDED instances can be triggered")
            if not isinstance(instance.contract, Vault):
                raise ValueError("Only Vault instances can be triggered")

            spending_vaults.append(manager.instances[idx])

        inputs_total_amount = sum(ci.get_value() for ci in spending_vaults)

        # construct the CTV template

        ctv_tmpl = CTransaction()
        ctv_tmpl.nVersion = 2
        ctv_tmpl.vin = [CTxIn(nSequence=10)]

        outputs = parse_outputs(json.loads(args_dict["outputs"]))
        outputs_total_amount = sum(out[1] for out in outputs)

        if outputs_total_amount > inputs_total_amount:
            print("Outputs amount is greater than inputs amount")
            return

        revault_amount = inputs_total_amount - outputs_total_amount

        # prepare template hash
        ctv_tmpl.vout = []
        for address, amount in outputs:
            ctv_tmpl.vout.append(CTxOut(
                nValue=amount,
                scriptPubKey=segwit_addr_to_scriptpubkey(address)
            )
            )

        # we assume the output is spent as first input later in the withdrawal transaction
        ctv_hash = ctv_tmpl.get_standard_template_hash(nIn=0)

        # sort vault UTXOs by decreasing amount value
        sorted_spending_vaults = sorted(spending_vaults, key=lambda v: v.get_value(), reverse=True)

        spends = []
        for (i, v) in enumerate(sorted_spending_vaults):
            if i == 0 and revault_amount > 0:
                # if there's a revault amount, we split the largest UTXO and revault the difference.
                # at this time, we don't support partially revaulting from multiple UTXOs
                # (which might perhaps be useful for UTXO management in a real vault)
                if revault_amount > v.get_value():
                    raise ValueError(
                        f"Input's amount {v.get_value()} is not enough for the revault amount {revault_amount}")
                spends.append(
                    (v, "trigger_and_revault", {"out_i": 0, "revault_out_i": 1, "ctv_hash": ctv_hash})
                )
            else:
                spends.append(
                    (v, "trigger", {"out_i": 0, "ctv_hash": ctv_hash})
                )

        spend_tx, sighashes = manager.get_spend_tx(spends, output_amounts={1: revault_amount})

        spend_tx.wit.vtxinwit = []

        sigs = [key.sign_schnorr(unvault_priv_key.privkey, sighash) for sighash in sighashes]

        for i, (_, action, args) in enumerate(spends):
            spend_tx.wit.vtxinwit.append(manager.get_spend_wit(
                spending_vaults[i],
                action,
                {**args, "sig": sigs[i]}
            ))

        print("Waiting for trigger transaction to be confirmed...")
        result = manager.spend_and_wait(spending_vaults, spend_tx)

        # store the template for later reference
        ctv_templates[ctv_hash] = ctv_tmpl

        print("Done")

    elif action == "recover":
        item_idx = int(args_dict["item"])
        instance = manager.instances[item_idx]
        if instance.status != ContractInstanceStatus.FUNDED:
            raise ValueError("Only FUNDED instances can be recovered")
        if not isinstance(instance.contract, (Vault, Unvaulting)):
            raise ValueError("Only Vault or Unvaulting instances can be recovered")

        instance("recover")(out_i=0)

    elif action == "withdraw":
        item_idx = int(args_dict["item"])
        instance = manager.instances[item_idx]
        if instance.status != ContractInstanceStatus.FUNDED or not isinstance(instance.contract, Unvaulting):
            raise ValueError("Only FUNDED, Unvaulting instances can be withdrawn")

        ctv_hash = instance.data
        spend_tx, _ = manager.get_spend_tx(
            (instance, "withdraw", {"ctv_hash": ctv_hash})
        )

        # TODO: get_spend_wit does not fill the transaction
        # according to the template (which the manager doesn't know)
        # Figure out a better way to let the framework handle this
        spend_tx.wit.vtxinwit = [manager.get_spend_wit(
            instance,
            "withdraw",
            {"ctv_hash": ctv_hash}
        )]

        spend_tx.nVersion = ctv_templates[ctv_hash].nVersion
        spend_tx.nLockTime = ctv_templates[ctv_hash].nLockTime
        spend_tx.vin[0].nSequence = ctv_templates[ctv_hash].vin[0].nSequence  # we assume only 1 input
        spend_tx.vout = ctv_templates[ctv_hash].vout

        print("Waiting for withdrawal to be confirmed...")
        print(spend_tx)
        result = manager.spend_and_wait(instance, spend_tx)
        print("Done")

    elif action == "fund":
        amount = int(args_dict["amount"])
        manager.fund_instance(V, amount)


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

    actions = ["fund", "mine", "list", "printall", "recover", "trigger", "withdraw"]

    unvault_priv_key = key.ExtendedKey.deserialize(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN")
    recover_priv_key = key.ExtendedKey.deserialize(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ")

    rpc = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}")

    V = Vault(None, 10, recover_priv_key.pubkey[1:], unvault_priv_key.pubkey[1:])

    manager = ContractManager(rpc, mine_automatically=args.mine_automatically)
    environment = Environment(rpc, manager, None, None, False)

    print(f"Vault address: {V.get_address()}\n")

    # map from known ctv hashes to the corresponding template (used for withdrawals)
    ctv_templates: Dict[bytes, CTransaction] = {}

    if args.script:
        script_main(args.script)
    else:
        try:
            cli_main()
        except (KeyboardInterrupt, EOFError):
            pass  # exit
