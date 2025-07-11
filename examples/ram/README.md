# RAM

`ram.py` is a simple contract that allows a Script to commit to some memory, and modify it in successive executions.

It is a building block for more complex smart contracts that require "memory" access.

## Prerequisites

After following the [root prerequisites](../..#prerequisites), make sure to install the additional requirements:

```bash
$ uv sync --extra ram
```

<details>
  <summary> Sample out of RAM extra packages being installed </summary>

  ```bash
  $ uv sync --extra ram
  > Resolved 30 packages in 0.37ms
  > Installed 3 packages in 3ms
  >  + prompt-toolkit==3.0.51
  >  + python-dotenv==0.13.0
  >  + wcwidth==0.2.13
  ```
</details>

## How to Run

`ram.py` is a command line tool that allows to create, manage and spend the Vault UTXOs.

To run the script, navigate to the directory containing `vault.py` and use the following command:

```bash
python examples/ram/ram.py -m
```

<details>
  <summary> Sample output of command with backend-image running </summary>

  ```bash
  $ python examples/ram/ram.py -m
  > ...
  > ...
  > ...
  > ...
  > ...
  ```
</details>

## Command-line Arguments

- `--mine-automatically` or `-m`: Enables automatic mining any time transactions are broadcast (assuming a wallet is loaded in bitcoin-core).
- `--script` or `-s`: Executes commands from a specified script file, instead of running the interactive CLI interface. Some examples are in the (script)[scripts] folder.

## Interactive Commands

While typing commands in interactive mode, the script offers auto-completion features to assist you.

You can use the following commands to work with regtest:
- `fund`: Funds the vault with a specified amount.
- `mine [n]`: mines 1 or `n` blocks.

The following commands allows to inspect the current state and history of known UTXOs:

- `list`: Lists available UTXOs known to the ContractManager.
- `printall`: Prints in a nice formats for Markdown all the transactions from known UTXOs.

The following commands implement specific features of the vault UTXOs (trigger, recover, withdraw). Autocompletion can help

- `withdraw`: Given the proof for the value of an element, withdraw from the contract.
- `write i value`: Given a valid proof for the value of the `i`-th element, updates the state but replacing it with `value`.
