"""
Vaults as described in https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2023-April/021588.html
"""

import argparse
import json

import os

import logging
import shlex

from dotenv import load_dotenv

from prompt_toolkit import prompt
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import FileHistory

from btctools.auth_proxy import AuthServiceProxy

import btctools.key as key
from btctools.messages import CTransaction, CTxIn, CTxOut
from btctools.segwit_addr import decode_segwit_address
from environment import Environment
from matt import ContractInstance, ContractInstanceStatus, ContractManager

from vault_contracts import Unvaulting, Vault

logging.basicConfig(filename='matt-cli.log', level=logging.DEBUG)


class ActionArgumentCompleter(Completer):
    ACTION_ARGUMENTS = {
        "fund": ["amount="],
        "list": [],
        "recover": ["item="],
        "trigger": ["items=\"[", "address="],
        "withdraw": ["item="], # TODO: allow multiple items?
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

rpc_user = os.getenv("RPC_USER")
rpc_password = os.getenv("RPC_PASSWORD")
rpc_host = os.getenv("RPC_HOST")
rpc_port = os.getenv("RPC_PORT")


def segwit_addr_to_scriptpubkey(addr: str) -> bytes:
    wit_ver, wit_prog = decode_segwit_address("bcrt", addr)

    if wit_ver is None or wit_prog is None:
        raise ValueError(f"Invalid segwit address (or wrong network): {addr}")

    return bytes([
        wit_ver + (0x50 if wit_ver > 0 else 0),
        len(wit_prog),
        *wit_prog
    ])


def main():
    while True:
        try:
            input_line = prompt("₿ ", history=history, completer=completer)

            # Split into a command and the list of arguments
            try:
                input_line_list = shlex.split(input_line)
            except ValueError as e:
                print(f"Invalid command: {str(e)}")
                continue

            # Ensure input_line_list is not empty
            if input_line_list:
                action = input_line_list[0].strip()
            else:
                continue

            # Get the necessary arguments from input_command_list
            args_dict = {}
            for item in input_line_list[1:]:
                param, value = item.split('=', 1)
                args_dict[param] = value

            if action == "":
                continue
            elif action not in actions:
                print("Invalid action")
                continue
            elif action == "list":
                for i, instance in enumerate(manager.instances):
                    print(i, instance.status, instance)
            elif action == "trigger":
                items_idx = json.loads(args_dict["items"])
                print("Triggering: ", items_idx)

                if not isinstance(items_idx, list) or len(set(items_idx)) != len(items_idx):
                    raise ValueError("Invalid items")

                spending_vaults: list[ContractInstance] = []
                for idx in items_idx:
                    if idx >= len(manager.instances):
                        raise ValueError(f"No such instance: {idx}")
                    instance: ContractInstance = manager.instances[idx]
                    if instance.status != ContractInstanceStatus.FUNDED:
                        raise ValueError("Only FUNDED instances can be triggered")
                    if not isinstance(instance.contract, Vault):
                        raise ValueError("Only Vault instances can be triggered")

                    spending_vaults.append(manager.instances[idx])

                # construct the CTV template

                ctv_tmpl = CTransaction()
                ctv_tmpl.nVersion = 2
                ctv_tmpl.vin = [CTxIn(nSequence=10)]
                ctv_tmpl.vout = [
                    CTxOut(
                        nValue=sum(v.funding_tx.vout[v.outpoint.n].nValue for v in spending_vaults),
                        scriptPubKey=segwit_addr_to_scriptpubkey(args_dict["address"])
                    )
                ]

                # we assume the output is spent as first input
                ctv_hash = ctv_tmpl.get_standard_template_hash(nIn=0)

                # store the template for later reference
                ctv_templates[ctv_hash] = ctv_tmpl

                spend_tx, sighashes = manager.get_spend_tx(
                    [(out, "trigger", {"out_i": 0, "ctv_hash": ctv_hash}) for out in spending_vaults]
                )
                print(spend_tx)
                print(sighashes)

                sigs = [key.sign_schnorr(unvault_priv_key.privkey, sighash) for sighash in sighashes]
                spend_tx.wit.vtxinwit = [manager.get_spend_wit(
                    spending_vaults[i],
                    "trigger",
                    {"out_i": 0, "ctv_hash": ctv_hash, "sig": sigs[i]}
                )
                    for i in range(len(items_idx))
                ]

                print("Waiting for trigger transaction to be confirmed...")
                result = manager.spend_and_wait(spending_vaults, spend_tx)
                print("Done")

            elif action == "recover":
                item_idx = int(args_dict["item"])
                instance = manager.instances[item_idx]
                if instance.status != ContractInstanceStatus.FUNDED:
                    raise ValueError("Only FUNDED instances can be recovered")
                if not isinstance(instance.contract, (Vault, Unvaulting)):
                    raise ValueError("Only Vault or Unvaulting instances can be recovered")

                spend_tx, _ = manager.get_spend_tx((instance, "recover", {"out_i": 0}))

                spend_tx.wit.vtxinwit = [manager.get_spend_wit(
                    instance,
                    "recover",
                    {"out_i": 0}
                )]

                print("Waiting for recover transaction to be confirmed...")
                print(spend_tx)
                result = manager.spend_and_wait(instance, spend_tx)
                print("Done")

            elif action == "withdraw":
                item_idx = int(args_dict["item"])
                instance = manager.instances[item_idx]
                if instance.status != ContractInstanceStatus.FUNDED or not isinstance(instance.contract, Unvaulting):
                    raise ValueError("Only FUNDED, Unvaulting instances can be withdrawn")

                ctv_hash = instance.data
                spend_tx, _ = manager.get_spend_tx(
                    (instance, "withdraw", {"ctv_hash": ctv_hash})
                )

                # TODO: get_spend_wit this does not fill the transaction
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
                V_inst = ContractInstance(V)
                manager.add_instance(V_inst)
                txid = rpc.sendtoaddress(V_inst.get_address(), amount/100_000_000)
                print(f"Waiting for funding transaction {txid} to be confirmed...")
                manager.wait_for_outpoint(V_inst, txid)
                print(V_inst.funding_tx)
        except (KeyboardInterrupt, EOFError):
            raise  # exit
        except Exception as err:
            print(f"Error: {err}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Non-interactive option
    parser.add_argument("--non-interactive", "-n", action="store_true", help="Run in non-interactive mode")

    # Mine automatically option
    parser.add_argument("--mine-automatically", "-m", action="store_true", help="Mine automatically")

    # Host option
    parser.add_argument("--host", default="localhost", type=str, help="Host address (default: localhost)")

    # Port option
    parser.add_argument("--port", default=12345, type=int, help="Port number (default: 12345)")

    args = parser.parse_args()

    actions = ["fund", "list", "recover", "trigger", "withdraw"]

    completer = ActionArgumentCompleter()
    # Create a history object
    history = FileHistory('.cli-history')

    unvault_priv_key = key.ExtendedKey.deserialize(
        "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN")
    recover_priv_key = key.ExtendedKey.deserialize(
        "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ")

    rpc = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}")

    V = Vault(None, 10, recover_priv_key.pubkey[1:], unvault_priv_key.pubkey[1:])

    manager = ContractManager([], rpc, mine_automatically=args.mine_automatically)
    environment = Environment(rpc, manager, args.host, args.port, not args.non_interactive)

    print(f"Vault address: {V.get_address()}\n")

    # map from known ctv hashes to the corresponding template (used for withdrawals)
    ctv_templates: dict[bytes, CTransaction] = {}

    try:
        main()
    except (KeyboardInterrupt, EOFError):
        pass  # exit
