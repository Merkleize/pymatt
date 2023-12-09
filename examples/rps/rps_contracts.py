import hashlib

from matt.argtypes import BytesType, IntType, SignerType
from matt.btctools.messages import sha256
from matt.btctools import script
from matt.btctools.script import OP_ADD, OP_CAT, OP_CHECKCONTRACTVERIFY, OP_CHECKSIG, OP_CHECKTEMPLATEVERIFY, OP_DUP, OP_ENDIF, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_IF, OP_LESSTHAN, OP_OVER, OP_SHA256, OP_SUB, OP_SWAP, OP_TOALTSTACK, OP_VERIFY, OP_WITHIN, CScript, bn2vch
from matt import CCV_FLAG_CHECK_INPUT, NUMS_KEY, P2TR, ClauseOutput, StandardClause, StandardP2TR, StandardAugmentedP2TR
from matt.utils import make_ctv_template

DEFAULT_STAKE: int = 1000  # amount of sats that the players bet


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


# params:
#  - alice_pk
#  - bob_pk
#  - c_a
# spending conditions:
#  - bob_pk    (m_b) => RPSGameS1[m_b]
class RPSGameS0(StandardP2TR):
    def __init__(self, alice_pk: bytes, bob_pk: bytes, c_a: bytes, stake: int = DEFAULT_STAKE):
        assert len(alice_pk) == 32 and len(bob_pk) == 32 and len(c_a) == 32

        self.alice_pk = alice_pk
        self.bob_pk = bob_pk
        self.c_a = c_a
        self.stake = stake

        S1 = RPSGameS1(alice_pk, bob_pk, c_a, stake)

        # witness: <m_b> <bob_sig>
        bob_move = StandardClause(
            name="bob_move",
            script=CScript([
                bob_pk,
                OP_CHECKSIG,
                OP_SWAP,

                # stack on successful signature check: <1> <m_b>

                OP_DUP, 0, 3, OP_WITHIN, OP_VERIFY,   # check that m_b is 0, 1 or 2

                OP_SHA256,  # data = sha256(m_b)
                0,  # index
                0,  # NUMS pk
                S1.get_taptree(),
                0,  # flags
                OP_CHECKCONTRACTVERIFY,
            ]),
            arg_specs=[
                ('m_b', IntType()),
                ('bob_sig', SignerType(bob_pk)),
            ],
            next_output_fn=lambda args: [ClauseOutput(n=0, next_contract=S1, next_data=sha256(bn2vch(args['m_b'])))]
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
    def __init__(self, alice_pk: bytes, bob_pk: bytes, c_a: bytes, stake: int):
        self.alice_pk = alice_pk
        self.bob_pk = bob_pk
        self.c_a = c_a
        self.stake = stake

        def make_script(diff: int, ctv_hash: bytes):
            # diff is (m_b - m_a) % 3
            assert 0 <= diff <= 2
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
                0,   # NUMS pubkey
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

                diff,          # draw / Bob wins / Alice wins, respectively
                OP_EQUALVERIFY,

                ctv_hash,
                OP_CHECKTEMPLATEVERIFY
            ])

        alice_spk = P2TR(self.alice_pk, []).get_tr_info().scriptPubKey
        bob_spk = P2TR(self.bob_pk, []).get_tr_info().scriptPubKey

        tmpl_alice_wins = make_ctv_template([(alice_spk, 2*self.stake)])
        tmpl_bob_wins = make_ctv_template([(bob_spk, 2*self.stake)])
        tmpl_tie = make_ctv_template([
            (alice_spk, self.stake),
            (bob_spk, self.stake),
        ])

        arg_specs = [
            ('m_b', IntType()),
            ('m_a', IntType()),
            ('r_a', BytesType()),
        ]
        alice_wins = StandardClause("tie", make_script(0, tmpl_alice_wins.get_standard_template_hash(0)), arg_specs, lambda _: tmpl_alice_wins)
        bob_wins = StandardClause("bob_wins", make_script(1, tmpl_bob_wins.get_standard_template_hash(0)), arg_specs, lambda _: tmpl_bob_wins)
        tie = StandardClause("alice_wins", make_script(2, tmpl_tie.get_standard_template_hash(0)), arg_specs, lambda _: tmpl_tie)

        super().__init__(NUMS_KEY, [alice_wins, bob_wins, tie])
