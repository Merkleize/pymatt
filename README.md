# pymatt

## WIP Python framework for MATT smart contracts

This repository contains a (very much Work In Progress) framework to create and test
smart contracts using the `OP_CHECKCONTRACTVERIFY` opcode of MATT.

## Prerequisites

  * [python](https://www.python.org) (3.9+)
  * [pip](https://pypi.org/project/pip)
  * [docker](https://www.docker.com)

## Installing the library

Optionally, create a python environment:

```bash
$ python -m venv venv
$ source venv/bin/activate
```

Install the library with:

```bash
$ pip install pymatt
```

### Run bitcoin-inquisition MATT in regtest mode

The fastest way to get started is [this docker container](https://github.com/Merkleize/docker):

```bash
$ docker pull bigspider/bitcoin_matt
$ docker run -d -p 18443:18443 bigspider/bitcoin_matt
```

### Case studies

The `examples` folder contains some utility scripts to work with regtest bitcoin-core:
- [init.sh](examples/init.sh) creates/loads and funds a wallet named `testwallet`. Run it once before the
examples and you're good to go.
- [fund.sh](examples/fund.sh) that allows to fund a certain address.

The following examples are currently implemented

- [Vault](examples/vault) [cli]: an implementation of a vault, largely compatible with [OP_VAULT BIP-0345](https://github.com/bitcoin/bips/pull/1421).
- [Rock-Paper-Scissors](examples/rps) [cli]: play Rock-Paper-Scissors on bitcoin.
- [RAM](examples/ram) [cli]: a a contract that uses a Merkle tree to store a vector of arbitrary
length in size, with transitions that allow to modify one element of the vector.
- [game256](examples/game256): Implements an end-2-end execution of the toy example for fraud proofs [drafted in bitcoin-dev](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-November/021205.html).

For the ones marked with [cli], a simple interactive tool allows to play with the contract.
More code examples can be found in the test suite.

## Docs

See the [docs](./docs) folder for high-level documentation on how to design smart contracts using MATT.

As the framework is still in development, we recommend looking at the code examples below for
developer documentation on using pymatt.

## Contribution

### Prerequisites

* [git](https://git-scm.com/) - --fast-version-control
* [uv](https://docs.astral.sh/uv) - extremely fast Python package & project manager written in Rust


The following guide walks through setting up your local working environment using `git`
as distributed version control system and `uv` as Python package and version manager.
If you do not have `git` installed, run the following command.

<details>
  <summary> Install using Homebrew (Darwin) </summary>
  
  ```bash
  brew install git
  ```
</details>

<details>
  <summary> Install via binary installer (Linux) </summary>
  
  * Debian-based package management
  ```bash
  sudo apt install git-all
  ```

  * Fedora-based package management
  ```bash
  sudo dnf install git-all
  ```
</details>

If you do not have `uv` installed, run the following command.

<details>
  <summary> Install using Homebrew (Darwin) </summary>

  ```bash
  brew install uv
  ```
</details>

<details>
  <summary> Install using standalone installer (Darwin and Linux) </summary>

  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```
</details>

Once you have `git` distributed version control system installed, you can
clone the current repository and  install any version of Python above version
3.9 for this project. The following commands help you set up and activate a
Python virtual environment where `uv` can download project dependencies from the `PyPI`
open-sourced registry defined under `pyproject.toml` file.

<details>
  <summary> Set up environment and synchronize project dependencies </summary>

  ```bash
  git clone git@github.com:Merkleize/pymatt.git
  cd pymatt
  uv venv --python 3.9
  source .venv/bin/activate
  uv sync --dev
  ```
</details>

### Run examples

All the examples use the `RPC_USER`, `RPC_PASSWORD`, `RPC_HOST`, `RPC_PORT` environment variables
to set up a connection with the regtest bitcoin node; the default values are the same as set
in the container.

If they differ in your system, make sure to set them appropriately, or create a `.env` file
similar to the following:

```
RPC_HOST = "localhost"
RPC_USER = "rpcuser"
RPC_PASSWORD = "rpcpass"
RPC_PORT = "18443"
```

NOTE: the examples do not handle fee management and will send transactions with 0 fees; those
are rejected with the default settings of bitcoin-core.

If not using the container above, please see an [example of custom bitcoin.conf](https://github.com/Merkleize/docker/blob/master/bitcoin.conf)
to work with the scripts in this repository.

You can use the following command to install the extra dependencies required for
running the examples attached.

<details>
  <summary> Install dependencies for `RAM` example </summary>

  ```bash
  uv sync --dev --extra ram
  ```
</details>

<details>
  <summary> Install dependencies for `Rps` example </summary>

  ```bash
  uv sync --dev --extra rps
  ```
</details>

<details>
  <summary> Install dependencies for `Vault` example </summary>

  ```bash
  uv sync --dev --extra vault
  ```
</details>

### Tests

This project uses `pytest` to run automated tests. Install the dependencies with:

```bash
uv sync --dev
```

<details>
  <summary> Sample installation output for development dependencies </summary>

  ```bash
  $ uv sync --dev
  > Resolved 30 packages in 0.35ms
  > Installed 24 packages in 124ms
  >  + attrs==25.3.0
  >  + bokeh==3.1.1
  >  + contourpy==1.1.1
  >  + iniconfig==2.1.0
  >  + jinja2==3.1.6
  >  + markupsafe==2.1.5
  >  + matt==0.0.1 (from file:///path/to/your/local/workspace/pymatt)
  >  + networkx==3.1
  >  + numpy==1.24.4
  >  + packaging==25.0
  >  + pandas==2.0.3
  >  + pillow==10.4.0
  >  + pluggy==1.5.0
  >  + py==1.11.0
  >  + pytest==6.2.5
  >  + python-dateutil==2.9.0.post0
  >  + pytz==2025.2
  >  + pyyaml==6.0.2
  >  + six==1.17.0
  >  + toml==0.10.2
  >  + tornado==6.4.2
  >  + typing-extensions==4.13.2
  >  + tzdata==2025.2
  >  + xyzservices==2025.4.0
  ```
</details>

The test suite requires a running instance of the MATT-enabled bitcoin-inquisition,
for example using the container above. The [init.sh](examples/init.sh) script makes
sure that a funded test wallet is loaded.

```bash
$ docker run -d -p 18443:18443 bigspider/bitcoin_matt
$ bash ./examples/init.sh
```

Then, run the tests with 

```bash
$ pytest
```

Refer to the [pytest documentation](https://docs.pytest.org/) for more advanced options.

### Report

Some tests produce additional illustrative info about the transactions produced during
the contract execution, in a Markdown report called `report.md`.
