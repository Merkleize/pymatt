# WIP Python framework for MATT smart contracts

This repository contains a (very much Work In Progress) framework to create and test smart contracts using the `OP_CHECKCONTRACVERIFY` opcode of MATT.

Install the requirements with:

```bash
$ pip install -r requirements.txt
```

# Case studies
The following examples assume that `OP_CHECKCONTRACVERIFY`, `OP_CAT` and `OP_CHECKTEMPLATEVERIFY` are available in a running regtest.

The fastest way to get started is [this docker container](https://github.com/Merkleize/docker):

```bash
$ docker pull docker pull bigspider/bitcoin_matt

$ docker run -d -p 18443:18443 bigspider/bitcoin_matt
```

## Vault

Implements a vault similar to the one described in [this bitcoin-dev post](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2023-April/021588.html).

Run the demo with:

```console
$ python vault.py
```

`vault.py` is a command line tool that allows to create, manage and spend UTXOs using

## Rock-Paper-Scissors

Rock-Paper-Scissors is an interactive game between two players who lock some money into a UTXO, and then proceed to play the game; the winner will get the sats.

Play as Alice:

```console
$ python rps.py --alice --rock
```

On a separate terminal, play as Bob:

```console
$ python rps.py --alice --scissors
```

The two scripts will communicate via a socket in order to coordinate the initial UTXO creation; once the game is funded, they take turns to spend it according to the rules.