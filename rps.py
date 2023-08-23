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
import subprocess

from dotenv import load_dotenv
from btctools.segwit_addr import encode_segwit_address
from btctools.auth_proxy import AuthServiceProxy

import btctools.key as key
from btctools.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, sha256
import btctools.script as script
from matt import P2TR, ContractInstance, ContractManager
from utils import wait_for_spending_tx

from rps_contracts import RPSGameS0, RPSGameS1

# point with provably unknown private key
NUMS_KEY: bytes = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

STAKE: int = 1000  # amount of sats that the players bet


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


class Player:
    def __init__(self, args: argparse.Namespace):
        self.args = args

    def get_rpc(self) -> AuthServiceProxy:
        return AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}")

    def mine(self, n_blocks: int = 1):
        if self.args.mine_automatically:
            subprocess.run(["bitcoin-cli", "-regtest", "-generate", str(n_blocks)], capture_output=True, text=True)

    def prompt(self, message: str | None = None):
        if message is not None:
            print(message)
        if not self.args.non_interactive:
            print("Press Enter to continue...")
            input()


class AliceGame(Player):
    def __init__(self, args: argparse.Namespace):
        super().__init__(args)

        self.priv_key = key.ExtendedKey.deserialize("xprv9s21ZrQH143K27gyeEkz5fzM5q8bZpsu6erWk7BsseLKiQCUajwLYcuuzfix8SjH2KKBMGRRgaVg6W9HEnZZtARcqrTcbh2aM49ECCtcvq7")

    def start_session(self, m_a: int):
        assert 0 <= m_a <= 2

        print(f"Alice's move: {m_a} ({RPS.move_str(m_a)})")

        r_a = os.urandom(32)
        c_a = RPS.calculate_hash(m_a, r_a)

        print("Waiting for Bob...")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.args.host, self.args.port))
        s.listen(1)
        conn, _ = s.accept()

        pk_a = self.priv_key.pubkey[1:]  # x-only pubkey

        conn.send(json.dumps({'c_a': c_a.hex(), 'pk_a': pk_a.hex()}).encode())

        bob_msg = json.loads(conn.recv(1024).decode())

        pk_b = bytes.fromhex(bob_msg['pk_b'])
        print(f"Alice's state: m_a={m_a}, r_a={r_a.hex()}, c_a={c_a.hex()}, pk_a={pk_a.hex()}, pk_b={pk_b.hex()}")

        S0 = RPSGameS0(pk_a, pk_b, c_a)
        S0_addr = encode_segwit_address("bcrt", 1, bytes(S0.get_tr_info().scriptPubKey)[2:])

        print(f"Alice waiting for output: {S0_addr}")

        rpc = self.get_rpc()

        C = ContractInstance(S0)
        M = ContractManager([C], rpc, mine_automatically=self.args.mine_automatically)

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
        tx_payout = M.get_spend_tx(C2, outcome, args)
        tx_payout.wit.vtxinwit = [M.get_spend_wit(C2, outcome, args)]

        self.prompt("Broadcasting adjudication transaction")

        M.spend_and_wait(C2, tx_payout)

        s.close()


class BobGame(Player):
    def __init__(self, args: argparse.Namespace):
        super().__init__(args)

        self.priv_key = key.ExtendedKey.deserialize("xprv9s21ZrQH143K2a274KJPXNa1tzYfv68f1CqcTY1CAnHistRD9s1N34w3GRx5GbBv2jJpDsdDy49Zd8wEDwT9t5DRyzZjtoaCqcoHY1pjTsJ")

    def join_session(self, m_b: int):
        assert 0 <= m_b <= 2

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.connect((self.args.host, self.args.port))

        alice_message = json.loads(s.recv(1024).decode())

        c_a = bytes.fromhex(alice_message['c_a'])
        pk_a = bytes.fromhex(alice_message['pk_a'])
        pk_b = self.priv_key.pubkey[1:]  # x-only pubkey

        print(f"Bob's state: c_a={c_a.hex()}, pk_a={pk_a.hex()}, pk_b={pk_b.hex()}")

        s.send(json.dumps({'pk_b': pk_b.hex()}).encode())

        contract_S0 = RPSGameS0(pk_a, pk_b, c_a)

        contract_S0_addr = encode_segwit_address("bcrt", 1, bytes(contract_S0.get_tr_info().scriptPubKey)[2:])

        print(f"Bob waiting for output: {contract_S0_addr}")

        rpc = self.get_rpc()

        C = ContractInstance(contract_S0)
        M = ContractManager([C], rpc, mine_automatically=self.args.mine_automatically)

        M.wait_for_outpoint(C)

        # Make move

        m_b_hash = sha256(script.bn2vch(m_b))

        print(f"Bob's move: {m_b} ({RPS.move_str(m_b)})")
        print(f"Bob's move's hash: {m_b_hash.hex()}")

        tx = M.get_spend_tx(C, "bob_move", {'m_b': m_b})

        vout: list[CTxOut] = tx.vout
        vout[0].nValue = 2000  # TODO: add amount management in framework

        # TODO: add some utility to get the sighash, too
        # compute Bob's signature:
        sighash = script.TaprootSignatureHash(
            tx,
            [C.funding_tx.vout[C.outpoint.n]],
            input_index=0,
            hash_type=0,
            scriptpath=True,
            script=contract_S0.get_tr_info().leaves["bob_move"].script
        )
        bob_sig = key.sign_schnorr(self.priv_key.privkey, sighash)

        tx.wit.vtxinwit = [M.get_spend_wit(C, "bob_move", {'m_b': m_b, 'bob_sig': bob_sig})]

        self.prompt("Broadcasting Bob's move transaction")

        [C2] = M.spend_and_wait(C, tx)

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
    group_player.add_argument("--alice", "-a", action="store_true", help="Alice mode")
    group_player.add_argument("--bob", "-b", action="store_true", help="Bob mode")

    group_move = parser.add_mutually_exclusive_group(required=False)
    group_move.add_argument("--rock", action="store_true", help="Play Rock")
    group_move.add_argument("--paper", action="store_true", help="Play Paper")
    group_move.add_argument("--scissors", action="store_true", help="Play Scissors")

    # Non-interactive option
    parser.add_argument("--non-interactive", "-n", action="store_true", help="Run in non-interactive mode")

    # Mine automatically option
    parser.add_argument("--mine-automatically", "-m", action="store_true", help="Mine automatically")

    # Host option
    parser.add_argument("--host", default="localhost", type=str, help="Host address (default: localhost)")

    # Port option
    parser.add_argument("--port", default=12345, type=int, help="Port number (default: 12345)")

    # Host option
    parser.add_argument("--move", default="localhost", type=str, help="Host address (default: localhost)")

    args = parser.parse_args()

    move = None
    if args.rock:
        move = 0
    elif args.paper:
        move = 1
    elif args.scissors:
        move = 2

    if args.alice:
        a = AliceGame(args)
        m_a = move if move is not None else random.SystemRandom().randint(0, 2)
        a.start_session(m_a)
    else:
        b = BobGame(args)
        m_b = move if move is not None else random.SystemRandom().randint(0, 2)
        b.join_session(m_b)
