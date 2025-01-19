# Vault

The `vault.py` script provides a command-line and interactive interface for Bitcoin vault operations, similar to the one described in the linked [bitcoin-dev mailing list post](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2023-April/021588.html).

Compared to that prototype, this version uses the `CCV_FLAG_DEDUCT_OUTPUT_AMOUNT` to allow partial revaulting of a Vault UTXO. This was the only missing feature as compared to the implementation using `OP_VAULT` (albeit with some differences in the revaulting semantics).

It uses the `OP_CHECKCONTRACTVERIFY` and `OP_CHECKTEMPLATEVERIFY` opcodes.

## Prerequisites

After following the [root prerequisites](../..#prerequisites), make sure to install the additional requirements:

```bash
$ pip install -r requirements.txt
```

## How to Run

`vault.py` is a command line tool that allows to create, manage and spend the Vault UTXOs.

To run the script, navigate to the directory containing `vault.py` and use the following command:

```bash
$ python vault.py -m
```

## Command-line Arguments

- `--mine-automatically` or `-m`: Enables automatic mining any time transactions are broadcast (assuming a wallet is loaded in bitcoin-core).
- `--script` or `-s`: Executes commands from a specified script file, instead of running the interactive CLI interface. Some examples are in the [scripts](scripts) folder.

## Interactive Commands

While typing commands in interactive mode, the script offers auto-completion features to assist you.

You can use the following commands to work with regtest:
- `fund`: Funds the vault with a specified amount.
- `mine [n]`: mines 1 or `n` blocks.

The following commands allows to inspect the current state and history of known UTXOs:

- `list`: Lists available UTXOs known to the ContractManager.
- `printall`: Prints in a nice formats for Markdown all the transactions from known UTXOs.

The following commands implement specific features of the vault UTXOs (trigger, recover, withdraw). Autocompletion can help 

- `trigger`: Triggers an action with specified items and outputs.
- `recover`: Recovers an item. Can be applied to one or more Vault, or Unvaulting (triggered) UTXO.
- `withdraw`: Completes the withdrawal from the vault; will fail if the timelock of 10 blocks is not satisfied.

The `scripts` folder has some example of interactions with the vault.

## Minivault

A simplified construction that only uses `OP_CHECKCONTRACTVERIFY` (without using `OP_CHECKTEMPLATEVERIFY`) is implemented in [minivault_contracts.py](minivault_contracts.py). It has all the same features of the full construction, except that the final withdrawal must necessarily go entirely to a single P2TR address.

Check out [test_minivault.py](../../tests/test_minivault.py) to see how it would be used.
