from btctools.messages import CTransaction, CTxIn, CTxOut
from btctools.script import OP_ADD, OP_CAT, OP_CHECKCONTRACTVERIFY, OP_CHECKSIG, OP_CHECKTEMPLATEVERIFY, OP_DUP, OP_ENDIF, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_IF, OP_LESSTHAN, OP_OVER, OP_SHA256, OP_SUB, OP_SWAP, OP_TOALTSTACK, OP_VERIFY, OP_WITHIN, CScript
from matt import CCV_FLAG_CHECK_INPUT, P2TR, StandardClause, StandardP2TR, StandardAugmentedP2TR


# point with provably unknown private key
NUMS_KEY: bytes = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

STAKE: int = 1000  # amount of sats that the players bet


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

                diff,          # draw / Bob wins / Alice wins, respectively
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
