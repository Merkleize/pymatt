# WIP Python framework for MATT smart contracts

This repository contains a (very much Work In Progress) framework to create and test smart contracts using the `OP_CHECKCONTRACVERIFY` opcode of MATT.

# Prerequisites
## Installing the library

Optionally, create a python environment:

```bash
$ python -m venv venv
$ source venv/bin/activate
```

Install the library with:

```bash
$ pip install .
```

## Run bitcoin-inquisition MATT in regtest mode

The fastest way to get started is [this docker container](https://github.com/Merkleize/docker):

```bash
$ docker pull bigspider/bitcoin_matt

$ docker run -d -p 18443:18443 bigspider/bitcoin_matt
```

All the examples use the `RPC_USER`, `RPC_PASSWORD`, `RPC_HOST`, `RPC_PORT` environment variables to set up a connection with the regtest bitcoin node; the default values are the same as set in the container.

If they differ in your system, make sure to set them appropriately, or create a `.env` file similar to the following:

```
RPC_HOST = "localhost"
RPC_USER = "rpcuser"
RPC_PASSWORD = "rpcpass"
RPC_PORT = "18443"
```

NOTE: the examples do not handle fee management and will send transactions with 0 fees; those are rejected with the default settings of bitcoin-core.

If not using the container above, please see an [example of custom bitcoin.conf](https://github.com/Merkleize/docker/blob/master/bitcoin.conf) to work with the scripts in this repository.

# Case studies

The `examples` folder contains some utility scripts to work with regtest bitcoin-core:
- [init.sh](examples/init.sh) creates/loads and funds a wallet named `testwallet`. Run it once before the examples and you're good to go.
- [fund.sh](examples/fund.sh) that allows to fund a certain address.

The following examples are currently implemented

- [Vault](examples/vault) [cli]: an implementation of a vault, largely compatible with [OP_VAULT BIP-0345](https://github.com/bitcoin/bips/pull/1421).
- [Rock-Paper-Scissors](examples/rps) [cli]: play Rock-Paper-Scissors on bitcoin.
- [RAM](examples/ram) [cli]: a a contract that uses a Merkle tree to store a vector of arbitrary length in size, with transitions that allow to modify one element of the vector.
- [game256](examples/game256): Implements an end-2-end execution of the toy example for fraud proofs [drafted in bitcoin-dev](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-November/021205.html).

For the ones marked with [cli], a simple interactive tool allows to play with the contract. More code examples can be found in the test suite.

# Tests

This project uses `pytest` to run automated tests. Install it with:

```bash
$ pip install pytest
```

The test suite requires a running instance of the MATT-enabled bitcoin-inquisition, for example using the container above. The [init.sh](examples/init.sh) script makes sure that a funded test wallet is loaded.

```bash
$ docker run -d -p 18443:18443 bigspider/bitcoin_matt
$ bash ./examples/init.sh
```

Then, run the tests with 

```bash
$ pytest
```

Refer to the [pytest documentation](https://docs.pytest.org/) for more advanced options.

## Report

Some tests produce additional illustrative info about the transactions produced during the contract execution, in a Markdown report called `report.md`.