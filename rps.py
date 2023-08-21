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

from io import BytesIO
import argparse
import socket
import json
import hashlib
import random
import os
from typing import List, Tuple
import subprocess

from dotenv import load_dotenv
from btctools.segwit_addr import encode_segwit_address
from btctools.auth_proxy import AuthServiceProxy

import btctools.key as key
from btctools.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, sha256
from btctools.script import OP_ADD, OP_CAT, OP_CHECKCONTRACTVERIFY, OP_CHECKSIG, OP_CHECKTEMPLATEVERIFY, OP_DUP, OP_ENDIF, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_IF, OP_LESSTHAN, OP_NUMEQUALVERIFY, OP_OVER, OP_SHA256, OP_SUB, OP_SWAP, OP_TOALTSTACK, OP_VERIFY, OP_WITHIN, CScript, TaprootInfo
import btctools.script as script
from utils import wait_for_output, wait_for_spending_tx

# Flags for OP_CHECKCONTRACTVERIFY
CCV_FLAG_CHECK_INPUT: int = 1
CCV_FLAG_IGNORE_OUTPUT_AMOUNT: int = 2


# point with provably unknown private key
NUMS_KEY: bytes = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

STAKE: int = 1000  # amount of sats that the players bet


def vch2bn(s: bytes) -> int:
    """Convert bitcoin-specific little endian format to number."""
    if len(s) == 0:
        return 0
    # The most significant bit is the sign bit.
    is_negative = s[0] & 0x80 != 0
    # Mask off the sign bit.
    s_abs = bytes([s[0] & 0x7f]) + s[1:]
    v_abs = int.from_bytes(s_abs, 'little')
    # Return as negative number if it's negative.
    return -v_abs if is_negative else v_abs


class Clause:
    def __init__(self, name: str, script: CScript):
        self.name = name
        self.script = script

    def stack_elements_from_args(self, args: dict) -> List[bytes]:
        raise NotImplementedError

    def args_from_stack_elements(self, elements: List[bytes]) -> dict:
        raise NotImplementedError


StandardType = type[int] | type[bytes]


# A StandardClause encodes simple scripts where the witness is exactly
# a list of arguments, always in the same order, and each is either
# an integer or a byte array.
# Other types of generic treatable clauses could be defined (for example, a MiniscriptClause).
class StandardClause(Clause):
    def __init__(self, name: str, script: CScript, arg_specs: list[tuple[str, StandardType]]):
        super().__init__(name, script)
        self.arg_specs = arg_specs

        for _, arg_cls in self.arg_specs:
            if arg_cls not in [int, bytes]:
                raise ValueError(f"Unsupported type: {arg_cls.__name__}")

    def stack_elements_from_args(self, args: dict) -> list[bytes]:
        result: list[bytes] = []
        for arg_name, arg_cls in self.arg_specs:
            if arg_name not in args:
                raise ValueError(f"Missing argument: {arg_name}")
            arg_value = args[arg_name]
            if type(arg_value) != arg_cls:
                raise ValueError(f"Argument {arg_name} must be of type {arg_cls.__name__}, not {type(arg_value).__name__}")
            if arg_cls == int:
                result.append(script.bn2vch(arg_value))
            elif arg_cls == bytes:
                result.append(arg_value)
            else:
                raise ValueError("Unexpected type")  # this should never happen

        return result

    def args_from_stack_elements(self, elements: List[bytes]) -> dict:
        result: dict = {}
        if len(elements) != len(self.arg_specs):
            raise ValueError(f"Expected {len(self.arg_specs)} elements, not {len(elements)}")
        for i, (arg_name, arg_cls) in enumerate(self.arg_specs):
            if arg_cls == int:
                result[arg_name] = vch2bn(elements[i])
            elif arg_cls == bytes:
                result[arg_name] = elements[i]
            else:
                raise ValueError("Unexpected type")  # this should never happen
        return result


class P2TR:
    """
    A class representing a Pay-to-Taproot script.
    """

    def __init__(self, internal_pubkey: bytes, scripts: List[Tuple[str, CScript]]):
        assert len(internal_pubkey) == 32

        self.internal_pubkey = internal_pubkey
        self.scripts = scripts
        self.tr_info = script.taproot_construct(internal_pubkey, scripts)

    def get_tr_info(self) -> TaprootInfo:
        return self.tr_info

    def get_tx_out(self, value: int) -> CTxOut:
        return CTxOut(
            nValue=value,
            scriptPubKey=self.get_tr_info().scriptPubKey
        )


class AugmentedP2TR:
    """
    An abstract class representing a Pay-to-Taproot script with some embedded data.
    While the exact script can only be produced once the embedded data is known,
    the scripts and the "naked internal key" are decided in advance.
    """

    def __init__(self, naked_internal_pubkey: bytes):
        assert len(naked_internal_pubkey) == 32

        self.naked_internal_pubkey = naked_internal_pubkey

    def get_scripts(self) -> List[Tuple[str, CScript]]:
        raise NotImplementedError("This must be implemented in subclasses")

    def get_taptree(self) -> bytes:
        # use dummy data, since it doesn't affect the merkle root
        return self.get_tr_info(b'\0'*32).merkle_root

    def get_tr_info(self, data: bytes) -> TaprootInfo:
        assert len(data) == 32

        internal_pubkey, _ = key.tweak_add_pubkey(self.naked_internal_pubkey, data)

        return script.taproot_construct(internal_pubkey, self.get_scripts())

    def get_tx_out(self, value: int, data: bytes) -> CTxOut:
        return CTxOut(nValue=value, scriptPubKey=self.get_tr_info(data).scriptPubKey)


class StandardP2TR(P2TR):
    """
    A StandardP2TR where all the transitions are given by a StandardClause.
    """

    def __init__(self, internal_pubkey: bytes, clauses: list[StandardClause]):
        super().__init__(internal_pubkey, list(map(lambda x: (x.name, x.script), clauses)))
        self.clauses = clauses
        self._clauses_dict = {clause.name: clause for clause in clauses}

    def get_scripts(self) -> List[Tuple[str, CScript]]:
        return list(map(lambda clause: (clause.name, clause.script), self.clauses))

    def encode_args(self, clause_name: str, **args: dict) -> list[bytes]:
        return [
            *self._clauses_dict[clause_name].stack_elements_from_args(args),
            self.get_tr_info().leaves[clause_name].script,
            self.get_tr_info().controlblock_for_script_spend(clause_name),
        ]

    def decode_wit_stack(self, stack_elems: list[bytes]) -> tuple[str, dict]:
        leaf_hash = stack_elems[-2]

        clause_name = None
        for clause in self.clauses:
            if leaf_hash == self.get_tr_info().leaves[clause.name].script:
                clause_name = clause.name
                break
        if clause_name is None:
            raise ValueError("Clause not found")

        return clause_name, self._clauses_dict[clause_name].args_from_stack_elements(stack_elems[:-2])


class StandardAugmentedP2TR(AugmentedP2TR):
    """
    An AugmentedP2TR where all the transitions are given by a StandardClause.
    """

    def __init__(self, naked_internal_pubkey: bytes, clauses: list[StandardClause]):
        super().__init__(naked_internal_pubkey)
        self.clauses = clauses
        self._clauses_dict = {clause.name: clause for clause in clauses}

    def get_scripts(self) -> List[Tuple[str, CScript]]:
        return list(map(lambda clause: (clause.name, clause.script), self.clauses))

    def encode_args(self, clause_name: str, data: bytes, **args: dict) -> list[bytes]:
        return [
            *self._clauses_dict[clause_name].stack_elements_from_args(args),
            self.get_tr_info(data).leaves[clause_name].script,
            self.get_tr_info(data).controlblock_for_script_spend(clause_name),
        ]

    def decode_wit_stack(self, data: bytes, stack_elems: list[bytes]) -> tuple[str, dict]:
        leaf_hash = stack_elems[-2]

        clause_name = None
        for clause in self.clauses:
            if leaf_hash == self.get_tr_info(data).leaves[clause.name].script:
                clause_name = clause.name
                break
        if clause_name is None:
            raise ValueError("Clause not found")

        return clause_name, self._clauses_dict[clause_name].args_from_stack_elements(stack_elems[:-2])


# params:
#  - alice_pk
#  - bob_pk
#  - c_a
# spending conditions:
#  - bob_pk    (m_b) => RPSGameS0[m_b]
class RPSGameS0(StandardP2TR):
    def __init__(self, alice_pk: bytes, bob_pk: bytes, c_a: bytes):
        assert len(alice_pk) == 32 and len(bob_pk) == 32 and len(c_a) == 32

        self.alice_pk = alice_pk
        self.bob_pk = bob_pk
        self.c_a = c_a

        # witness: <m_b> <bob_sig>
        bob_move = StandardClause(
            "bob_move",
            CScript([
                bob_pk,
                OP_CHECKSIG,
                OP_SWAP,

                # stack on successful signature check: <1> <m_b>

                OP_DUP, 0, 3, OP_WITHIN, OP_VERIFY,   # check that m_b is 0, 1 or 2

                OP_SHA256,  # data = sha256(m_b)
                0,  # index
                0,  # NUMS pk
                RPSGameS1(alice_pk, bob_pk, c_a).get_taptree(),
                0,  # flags
                OP_CHECKCONTRACTVERIFY,
            ]), [
                ('m_b', int),
                ('bob_sig', bytes),
            ]
        )

        super().__init__(NUMS_KEY, [bob_move])


# params:
#  - alice_pk
#  - bob_pk
#  - c_a
# variables:
# - m_b
# spending conditions:
#  - alice_pk, reveal winning move => ctv(alice wins)
#  - alice_pk, reveal losing move => ctv(bob wins)
#  - alice_pk, reveal tie move => ctv(tie)
class RPSGameS1(StandardAugmentedP2TR):
    def __init__(self, alice_pk: bytes, bob_pk: bytes, c_a: bytes):
        self.alice_pk = alice_pk
        self.bob_pk = bob_pk
        self.c_a = c_a

        def make_script(outcome: int, ctv_hash: bytes):
            assert 0 <= outcome <= 2
            # witness: [<m_b> <m_a> <r_a>]

            return CScript([
                OP_OVER, OP_DUP, OP_TOALTSTACK,  # save m_a
                0, 3, OP_WITHIN, OP_VERIFY,      # check that m_a is 0, 1 or 2

                # stack: <m_b> <m_a> <r_a>        altstack: <m_a>

                # check that SHA256(m_a || r_a) equals c_a
                OP_CAT, OP_SHA256,
                self.c_a,
                OP_EQUALVERIFY,

                OP_DUP,
                # stack: <m_b> <m_b>              altstack: <m_a>

                OP_SHA256,  # data: sha256(m_b)
                -1,  # index: current input's index
                0,   # NUMS pubkey (TODO: can we use -1?)
                -1,  # taptree: current input's taptree
                CCV_FLAG_CHECK_INPUT,  # flags
                OP_CHECKCONTRACTVERIFY,

                # stack: <m_b>                    altstack: <m_a>

                OP_FROMALTSTACK,
                OP_SUB,

                # stack: <m_b - m_a>

                OP_DUP,           # if the result is negative, add 3
                0, OP_LESSTHAN,
                OP_IF,
                    3,
                    OP_ADD,
                OP_ENDIF,

                outcome,          # draw / Bob wins / Alice wins, respectively
                OP_EQUALVERIFY,

                ctv_hash,
                OP_CHECKTEMPLATEVERIFY
            ])

        def make_ctv_hash(alice_amount, bob_amount) -> bytes:
            tmpl = CTransaction()
            tmpl.nVersion = 2
            tmpl.vin = [CTxIn(nSequence=0)]
            if alice_amount > 0:
                tmpl.vout.append(
                    CTxOut(
                        nValue=alice_amount,
                        scriptPubKey=P2TR(self.alice_pk, []).get_tr_info().scriptPubKey
                    )
                )
            if bob_amount > 0:
                tmpl.vout.append(
                    CTxOut(
                        nValue=bob_amount,
                        scriptPubKey=P2TR(self.bob_pk, []).get_tr_info().scriptPubKey
                    )
                )
            return tmpl.get_standard_template_hash(0)  # TODO: why 0? Is it correct?

        ctvhash_alice_wins = make_ctv_hash(2*STAKE, 0)
        ctvhash_bob_wins = make_ctv_hash(0, 2*STAKE)
        ctvhash_tie = make_ctv_hash(STAKE, STAKE)

        arg_specs = [
            ('m_b', int),
            ('m_a', int),
            ('r_a', bytes),
        ]
        alice_wins = StandardClause("tie", make_script(0, ctvhash_tie), arg_specs)
        bob_wins = StandardClause("bob_wins", make_script(1, ctvhash_bob_wins), arg_specs)
        tie = StandardClause("alice_wins", make_script(2, ctvhash_alice_wins), arg_specs)

        super().__init__(NUMS_KEY, [alice_wins, bob_wins, tie])


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

        contract_S0 = RPSGameS0(pk_a, pk_b, c_a)

        contract_S0_addr = encode_segwit_address("bcrt", 1, bytes(contract_S0.get_tr_info().scriptPubKey)[2:])

        print(f"Alice waiting for output: {contract_S0_addr}")

        rpc = self.get_rpc()

        contract_S0_outpoint, last_height = wait_for_output(rpc, contract_S0.get_tr_info().scriptPubKey)

        # Wait for bob to spend it

        print("Waiting for Bob's move...")

        print(f"Outpoint: {hex(contract_S0_outpoint.hash)}:{contract_S0_outpoint.n}")
        tx, vin, last_height = wait_for_spending_tx(rpc, contract_S0_outpoint, starting_height=last_height)
        tx.rehash()

        # Decode bob's move

        in_wit: CTxInWitness = tx.wit.vtxinwit[vin]

        assert len(in_wit.scriptWitness.stack) == 4

        _, args = contract_S0.decode_wit_stack(in_wit.scriptWitness.stack)
        m_b: int = args['m_b']
        assert 0 <= m_b <= 2

        print(f"Bob's move: {m_b} ({RPS.move_str(m_b)}).")

        outcome = RPS.adjudicate(m_a, m_b)
        print(f"Game result: {outcome}")

        # TODO: Payout
        RPS_S1 = RPSGameS1(pk_a, pk_b, c_a)

        tx_payout = CTransaction()
        tx_payout.nVersion = 2
        tx_payout.vin = [
            CTxIn(nSequence=0, outpoint=COutPoint(int(tx.hash, 16), vin))
        ]
        if outcome == "alice_wins":
            tx_payout.vout = [
                CTxOut(
                    nValue=STAKE * 2,
                    scriptPubKey=P2TR(pk_a, []).get_tr_info().scriptPubKey
                )
            ]
        elif outcome == "bob_wins":
            tx_payout.vout = [
                CTxOut(
                    nValue=STAKE * 2,
                    scriptPubKey=P2TR(pk_b, []).get_tr_info().scriptPubKey
                )
            ]
        else:
            tx_payout.vout = [
                CTxOut(
                    nValue=STAKE,
                    scriptPubKey=P2TR(pk_a, []).get_tr_info().scriptPubKey
                ),
                CTxOut(
                    nValue=STAKE,
                    scriptPubKey=P2TR(pk_b, []).get_tr_info().scriptPubKey
                )
            ]

        m_b_hash = sha256(script.bn2vch(m_b))

        tx_payout.wit.vtxinwit = [CTxInWitness()]
        tx_payout.wit.vtxinwit[0].scriptWitness.stack = RPS_S1.encode_args(outcome, m_b_hash, m_b=m_b, m_a=m_a, r_a=r_a)

        self.prompt("Broadcasting adjudication transaction")
        txid = rpc.sendrawtransaction(tx_payout.serialize().hex())
        print(f"txid: {txid}")

        self.mine()

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

        contract_outpoint, last_height = wait_for_output(rpc, contract_S0.get_tr_info().scriptPubKey)
        outpoint_tx_raw = rpc.getrawtransaction(contract_outpoint.hash.to_bytes(32, byteorder="big").hex())
        outpoint_tx = CTransaction()
        outpoint_tx.deserialize(BytesIO(bytes.fromhex(outpoint_tx_raw)))

        # Make move

        m_b_hash = sha256(script.bn2vch(m_b))

        print(f"Bob's move: {m_b} ({RPS.move_str(m_b)})")
        print(f"Bob's move's hash: {m_b_hash.hex()}")

        S1 = RPSGameS1(pk_a, pk_b, c_a)

        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [
            CTxIn(outpoint=contract_outpoint)
        ]
        tx.vout = [
            CTxOut(
                nValue=outpoint_tx.vout[contract_outpoint.n].nValue,
                scriptPubKey=S1.get_tr_info(m_b_hash).scriptPubKey
            )
        ]

        # compute Bob's signature:
        sighash = script.TaprootSignatureHash(
            tx,
            [outpoint_tx.vout[contract_outpoint.n]],
            input_index=0,
            hash_type=0,
            scriptpath=True,
            script=contract_S0.get_tr_info().leaves["bob_move"].script
        )
        bob_sig = key.sign_schnorr(self.priv_key.privkey, sighash)

        tx.wit.vtxinwit = [CTxInWitness()]

        tx.wit.vtxinwit[0].scriptWitness.stack = contract_S0.encode_args('bob_move', m_b=m_b, bob_sig=bob_sig)

        txid = tx.rehash()

        last_height = rpc.getblockcount()  # keep track of the bock height before we broadcast the transaction

        self.prompt("Broadcasting Bob's move transaction")
        rpc.sendrawtransaction(tx.serialize().hex())

        print(f"Bob's move broadcasted: {m_b}. txid: {txid}")

        self.mine()

        print("Waiting for adjudication")

        contract_S1_outpoint = COutPoint(int(txid, 16), 0)

        # Wait for Alice to adjudicate
        tx, vin, last_height = wait_for_spending_tx(rpc, contract_S1_outpoint, starting_height=last_height)
        in_wit: CTxInWitness = tx.wit.vtxinwit[vin]

        outcome, _ = S1.decode_wit_stack(m_b_hash, in_wit.scriptWitness.stack)

        print(f"Outcome: {outcome}")

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
