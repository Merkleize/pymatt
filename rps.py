"""
Implements the protocol described in https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2023-May/021599.html

### Setup

Alice has a pk_a, and bob has a pk_b.


Alice                                       Bob

choose m_a <-- {0, 1, 2}
r_a <$-- {0, 1}^256
c_a = SHA256(m_a)

                      pk_a, c_a
               |------------------------>

                                            Compute the RPS(c_a, pk_a, pk_b) UTXO
                                            Create a PSBTv2 psbt_game with his inputs, his change output, and the contract output
                pk_b, psbt_game_partial
               <------------------------|

Verify that RPS(c_a, pk_a, pk_b) is in the psbt.
Add her own inputs and change output, obtaining psbt_game.
Sign psbt_game.

                        psbt_game
               |------------------------>
                                            Sign psbt_game.
                                            Finalize the psbt, broadcast the transaction.


### Gameplay

Once the transaction is confirmed, bob both parties monitor the UTXO containing the game instance,
and play the moves when it's their turn, as per the rules.

"""

import argparse
import socket
import json
import hashlib
import random
import os

from dotenv import load_dotenv
from btctools.auth_proxy import AuthServiceProxy

import btctools.key as key
from btctools.messages import sha256
import btctools.script as script
from environment import Environment
from matt import ContractInstance, ContractManager

from rps_contracts import DEFAULT_STAKE, RPSGameS0


load_dotenv()

rpc_user = os.getenv("RPC_USER")
rpc_password = os.getenv("RPC_PASSWORD")
rpc_host = os.getenv("RPC_HOST")
rpc_port = os.getenv("RPC_PORT")


class RPS:
    @staticmethod
    def move_str(move: int) -> str:
        assert 0 <= move <= 2
        if move == 0:
            return "rock"
        elif move == 1:
            return "paper"
        else:
            return "scissors"

    @staticmethod
    def adjudicate(move_alice, move_bob):
        assert 0 <= move_alice <= 2 and 0 <= move_bob <= 2
        if move_bob == move_alice:
            return "tie"
        elif (move_bob - move_alice) % 3 == 2:
            return "alice_wins"
        else:
            return "bob_wins"

    @staticmethod
    def calculate_hash(move: int, r: bytes) -> bytes:
        assert 0 <= move <= 2 and len(r) == 32

        m = hashlib.sha256()
        m.update(script.bn2vch(move) + r)
        return m.digest()


class AliceGame:
    def __init__(self, env: Environment, args: dict):
        self.env = env
        self.args = args

        # TODO: use tprv
        self.priv_key = key.ExtendedKey.deserialize("xprv9s21ZrQH143K27gyeEkz5fzM5q8bZpsu6erWk7BsseLKiQCUajwLYcuuzfix8SjH2KKBMGRRgaVg6W9HEnZZtARcqrTcbh2aM49ECCtcvq7")

    def start_session(self, m_a: int):
        assert 0 <= m_a <= 2

        # Beginning of the protocol: exchange of pubkeys

        print(f"Alice's move: {m_a} ({RPS.move_str(m_a)})")

        r_a = os.urandom(32)
        c_a = RPS.calculate_hash(m_a, r_a)

        print("Waiting for Bob...")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.env.host, self.env.port))
        s.listen(1)
        conn, _ = s.accept()

        pk_a = self.priv_key.pubkey[1:]  # x-only pubkey

        conn.send(json.dumps({'c_a': c_a.hex(), 'pk_a': pk_a.hex()}).encode())

        bob_msg = json.loads(conn.recv(1024).decode())

        pk_b = bytes.fromhex(bob_msg['pk_b'])
        print(f"Alice's state: m_a={m_a}, r_a={r_a.hex()}, c_a={c_a.hex()}, pk_a={pk_a.hex()}, pk_b={pk_b.hex()}")

        M = self.env.manager

        # Create initial smart contract UTXO
        S0 = RPSGameS0(pk_a, pk_b, c_a)
        C = ContractInstance(S0)
        M.instances.append(C)  # TODO: add proper method to ContractManager

        if self.args.mine_automatically:
            print("Broadcasting funding transaction")
            environment.rpc.sendtoaddress(C.get_address(), 2 * DEFAULT_STAKE / 100_000_000)

        print(f"Alice waiting for output: {C.get_address()}")
        M.wait_for_outpoint(C)

        # Wait for bob to spend it

        print("Waiting for Bob's move...")

        print(f"Outpoint: {hex(C.outpoint.hash)}:{C.outpoint.n}")
        [C2] = M.wait_for_spend(C)

        # Decode bob's move
        m_b: int = C.spending_args['m_b']
        assert 0 <= m_b <= 2

        print(f"Bob's move: {m_b} ({RPS.move_str(m_b)}).")

        outcome = RPS.adjudicate(m_a, m_b)
        print(f"Game result: {outcome}")

        args = {
            "m_a": m_a,
            "m_b": m_b,
            "r_a": r_a,
        }
        tx_payout, _ = M.get_spend_tx([(C2, outcome, args)])
        tx_payout.wit.vtxinwit = [M.get_spend_wit(C2, outcome, args)]

        self.env.prompt("Broadcasting adjudication transaction")

        M.spend_and_wait(C2, tx_payout)

        s.close()


class BobGame:
    def __init__(self, env: Environment, args: dict):
        self.env = env
        self.args = args

        # TODO: use tprv
        self.priv_key = key.ExtendedKey.deserialize("xprv9s21ZrQH143K2a274KJPXNa1tzYfv68f1CqcTY1CAnHistRD9s1N34w3GRx5GbBv2jJpDsdDy49Zd8wEDwT9t5DRyzZjtoaCqcoHY1pjTsJ")

    def join_session(self, m_b: int):
        assert 0 <= m_b <= 2

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.connect((self.env.host, self.env.port))

        alice_message = json.loads(s.recv(1024).decode())

        c_a = bytes.fromhex(alice_message['c_a'])
        pk_a = bytes.fromhex(alice_message['pk_a'])
        pk_b = self.priv_key.pubkey[1:]  # x-only pubkey

        print(f"Bob's state: c_a={c_a.hex()}, pk_a={pk_a.hex()}, pk_b={pk_b.hex()}")

        s.send(json.dumps({'pk_b': pk_b.hex()}).encode())

        # Create initial smart contract UTXO

        S0 = RPSGameS0(pk_a, pk_b, c_a)
        C = ContractInstance(S0)
        M = self.env.manager

        print(f"Bob waiting for output: {C.get_address()}")

        M = ContractManager([C], rpc, mine_automatically=self.args.mine_automatically)

        M.wait_for_outpoint(C)

        # Make move

        m_b_hash = sha256(script.bn2vch(m_b))

        print(f"Bob's move: {m_b} ({RPS.move_str(m_b)})")
        print(f"Bob's move's hash: {m_b_hash.hex()}")

        tx, [sighash] = M.get_spend_tx([(C, "bob_move", {'m_b': m_b})])

        bob_sig = key.sign_schnorr(self.priv_key.privkey, sighash)

        tx.wit.vtxinwit = [M.get_spend_wit(C, "bob_move", {'m_b': m_b, 'bob_sig': bob_sig})]

        self.env.prompt("Broadcasting Bob's move transaction")

        [C2] = M.spend_and_wait([C], tx)

        txid = C.spending_tx.hash
        print(f"Bob's move broadcasted: {m_b}. txid: {txid}")

        print("Waiting for adjudication")

        # Wait for Alice to adjudicate
        M.wait_for_spend(C2)

        print(f"Outcome: {C2.spending_clause}")

        s.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Final command line arguments parser.",
                                     usage="%(prog)s [-a | -b] [-n] [-m] [--host HOST] [--port PORT]",
                                     epilog="Ensure that either --alice or --bob is provided.")

    # Group for mutually exclusive options: alice and bob
    group_player = parser.add_mutually_exclusive_group(required=True)
    group_player.add_argument("--alice", "-A", action="store_true", help="Play as Alice")
    group_player.add_argument("--bob", "-B", action="store_true", help="Play as Bob")

    group_move = parser.add_mutually_exclusive_group(required=False)
    group_move.add_argument("--rock", action="store_true", help="Play Rock")
    group_move.add_argument("--paper", action="store_true", help="Play Paper")
    group_move.add_argument("--scissors", action="store_true", help="Play Scissors")

    # Move option
    parser.add_argument("--move", default="localhost", type=str, help="Host address (default: localhost)")

    # Non-interactive option
    parser.add_argument("--non-interactive", "-n", action="store_true", help="Run in non-interactive mode")

    # Mine automatically option
    parser.add_argument("--mine-automatically", "-m", action="store_true", help="Mine automatically")

    # Host option
    parser.add_argument("--host", default="localhost", type=str, help="Host address (default: localhost)")

    # Port option
    parser.add_argument("--port", default=12345, type=int, help="Port number (default: 12345)")

    args = parser.parse_args()

    move = None
    if args.rock:
        move = 0
    elif args.paper:
        move = 1
    elif args.scissors:
        move = 2

    rpc = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}")

    manager = ContractManager([], rpc, mine_automatically=args.mine_automatically)
    environment = Environment(rpc, manager, args.host, args.port, not args.non_interactive)

    if args.alice:
        a = AliceGame(environment, args)
        m_a = move if move is not None else random.SystemRandom().randint(0, 2)
        a.start_session(m_a)
    else:
        b = BobGame(environment, args)
        m_b = move if move is not None else random.SystemRandom().randint(0, 2)
        b.join_session(m_b)
