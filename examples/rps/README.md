
# Rock, Paper, Scissors (RPS) with Bitcoin Protocol

This script implements the Rock, Paper, Scissors game based on a protocol described [here](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2023-May/021599.html).


## Prerequisites

After following the [root prerequisites](../..#prerequisites), make sure to install the additional requirements:

```bash
uv sync --extra rps
```

<details>
  <summary> Sample out of Rock-Paper-Scissors extra packages being installed </summary>

  ```bash
  $ uv sync --extra rps
  > Resolved 30 packages in 0.36ms
  > Installed 1 package in 1ms
  >  + python-dotenv==0.13.0
  ```
</details>

## How to Run:

The game can be played as either Alice or Bob, and you can specify your move (rock, paper, scissors). Additionally, other options like non-interactive mode and automatic mining can be set.

```bash
python examples/rps/rps.py --alice/--bob [--rock/--paper/--scissors] [--non-interactive] [--mine-automatically] [--host HOST] [--port PORT]
```

<details>
  <summary> Sample output of command with backend-image running </summary>

  ```bash
  $ python examples/rps/rps.py --alice --rock --non-interactive --mine-automatically --host localhost --port 18443
  > ...
  > ...
  > ...
  > ...
  > ...
  $ python examples/rps/rps.py --bob --paper --non-interactive --mine-automatically --host localhost --port 18443
  > ...
  > ...
  > ...
  > ...
  > ...
  ```
</details>

In order to play a game, run `python examples/rps/rps.py --alice` on a shell,
and `python examples/rps/rps.py --bob` on a separate shell.

The two scripts will establish a socket to communicate and negotiate a game UTXO.

Once the UTXO is funded (NOTE: it must be funded externally), the two scripts proceed to play the game. 

### Arguments:

- `--alice` / `--bob`: Specify the player you want to play as.
- `--rock` / `--paper` / `--scissors`: Specify your move. If ommitted, a random move is chosen.
- `--non-interactive`: Run in non-interactive mode (if not enabled, the user has to confirm each action).
- `--mine-automatically`: Enable automatic mining when transactions are broadcast.
- `--host`: Specify the host address (default is `localhost`).
- `--port`: Specify the port number (default is `12345`).
