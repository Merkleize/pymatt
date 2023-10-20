
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