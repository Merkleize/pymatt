# 256 game

`game256_contracts.py` implements the game of doubling 8 times, the toy example used in [this post](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-November/021205.html) to the bitcoin-dev mailing list.

There is no interactive tool to play with these contracts, but they are [tested](../../tests/test_fraud.py) in the pytest test suite.

The actual code of the bisection protocol smart contract, which is independent from the specific computation, is in [hub/fraud.py](../../matt/hub/fraud.py).
