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
$ docker pull docker pull bigspider/bitcoin_matt

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

- [Vault](examples/vault)
- [Rock-Paper-Scissors](examples/rps)
