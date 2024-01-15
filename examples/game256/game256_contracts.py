

from dataclasses import dataclass
from matt import NUMS_KEY
from matt.argtypes import BytesType, IntType, SignerType
from matt.btctools.common import sha256
from matt.btctools.script import OP_ADD, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_FROMALTSTACK, OP_NOT, OP_PICK, OP_ROT, OP_SHA256, OP_SWAP, OP_TOALTSTACK, OP_VERIFY, CScript
from matt.contracts import ClauseOutput, StandardClause, StandardAugmentedP2TR, StandardP2TR, ContractState
from matt.hub.fraud import Bisect_1, Computer, Leaf
from matt.merkle import MerkleTree
from matt.script_helpers import check_input_contract, check_output_contract, dup, merkle_root, older
from matt.utils import encode_wit_element

# Note: for simplicity, this contract does not yet implement bonds, nor slashing part of it after the fraud proof protocol.

# TODO: add forfait clauses whenever needed

# TODO: how to generalize what the contract does after the leaf? We should be able to compose clauses with some external code.
#       Do we need "clause" algebra?


class G256_S0(StandardP2TR):
    def __init__(self, alice_pk: bytes, bob_pk: bytes, forfait_timeout: int = 10):
        self.alice_pk = alice_pk
        self.bob_pk = bob_pk
        self.forfait_timeout = forfait_timeout

        g256_s1 = G256_S1(alice_pk, bob_pk, forfait_timeout)
        # witness: <bob_sig> <x>
        choose = StandardClause(
            name="choose",
            script=CScript([
                *g256_s1.State.encoder_script(),
                *check_output_contract(g256_s1),

                bob_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('bob_sig', SignerType(bob_pk)),
                ('x', IntType()),
            ],
            next_outputs_fn=lambda args, _: [ClauseOutput(
                n=-1,
                next_contract=g256_s1,
                next_state=g256_s1.State(x=args['x'])
            )]
        )

        super().__init__(NUMS_KEY, choose)


class G256_S1(StandardAugmentedP2TR):
    @dataclass
    class State(ContractState):
        x: int

        def encode(self):
            return sha256(encode_wit_element(self.x))

        def encoder_script():
            return CScript([OP_SHA256])

    def __init__(self, alice_pk: bytes, bob_pk: bytes, forfait_timeout):
        self.alice_pk = alice_pk
        self.bob_pk = bob_pk
        self.forfait_timeout = forfait_timeout

        g256_s2 = G256_S2(alice_pk, bob_pk, forfait_timeout)

        # reveal: <alice_sig> <t_a> <y> <sha256(x)>
        reveal = StandardClause(
            name="reveal",
            script=CScript([
                OP_DUP,

                # check that the top of the stack is the embedded data
                *self.State.encoder_script(),
                *check_input_contract(),

                # <alice_sig> <t_a> <y> <x>
                *g256_s2.State.encoder_script(),
                *check_output_contract(g256_s2),

                alice_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('alice_sig', SignerType(alice_pk)),
                ('t_a', BytesType()),
                ('y', IntType()),
                ('x', IntType()),
            ],
            next_outputs_fn=lambda args, _: [ClauseOutput(
                n=-1,
                next_contract=g256_s2,
                next_state=g256_s2.State(t_a=args['t_a'], y=args['y'], x=args['x'])
            )]
        )

        super().__init__(NUMS_KEY, reveal)


Compute2x = Computer(
    encoder=CScript([OP_SHA256]),
    func=CScript([OP_DUP, OP_ADD]),
    specs=[('x', IntType())],
)


NopInt = Computer(
    encoder=CScript([]),
    func=CScript([]),
    specs=[('x', IntType())],
)


class G256_S2(StandardAugmentedP2TR):
    @dataclass
    class State(ContractState):
        t_a: bytes
        y: int
        x: bytes

        def encode(self):
            return MerkleTree([self.t_a, sha256(encode_wit_element(self.y)), sha256(encode_wit_element(self.x))]).root

        def encoder_script():
            return CScript([
                OP_TOALTSTACK, OP_SHA256, OP_FROMALTSTACK, OP_SHA256,
                *merkle_root(3)
            ])

    def __init__(self, alice_pk: bytes, bob_pk: bytes, forfait_timeout: int = 10):
        self.alice_pk = alice_pk
        self.bob_pk = bob_pk
        self.forfait_timeout = forfait_timeout

        # reveal: <alice_sig>
        withdraw = StandardClause(
            name="withdraw",
            script=CScript([
                *older(forfait_timeout),

                alice_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[('alice_sig', SignerType(alice_pk))]
        )

        def leaf_factory(i: int): return Leaf(alice_pk, bob_pk, Compute2x)

        bisectg256_0 = Bisect_1(alice_pk, bob_pk, 0, 7, leaf_factory, forfait_timeout)
        # start_challenge: <bob_sig> <t_a> <y> <x> <z> <t_b>
        start_challenge = StandardClause(
            name="start_challenge",
            script=CScript([
                OP_TOALTSTACK,

                # check that y != z
                OP_DUP, 3, OP_PICK, OP_EQUAL, OP_NOT, OP_VERIFY,

                OP_TOALTSTACK,

                # <bob_sig> <t_a> <y> <x>  ---  <t_b> <z>

                *dup(3),

                # verify the embedded data
                *self.State.encoder_script(),
                *check_input_contract(),

                # <bob_sig> <t_a> <y> <x>  ---  <t_b> <z>
                OP_SHA256, OP_SWAP, OP_SHA256,
                # <bob_sig> <t_a> <sha256(x)> <sha256(y)>  ---  <t_b> <z>
                OP_ROT,
                # <bob_sig> <sha256(x)> <sha256(y)> <t_a>  ---  <t_b> <sha256(z)>

                OP_FROMALTSTACK, OP_SHA256,
                # <bob_sig> <sha256(x)> <sha256(y)> <t_a> <sha256(z)>  ---  <t_b>
                OP_SWAP,
                # <bob_sig> <sha256(x)> <sha256(y)> <sha256(z)> <t_a>  ---  <t_b>

                OP_FROMALTSTACK,

                # <bob_sig> <sha256(x)> <sha256(y)> <sha256(z)> <t_a> <t_b>

                *bisectg256_0.State.encoder_script(),
                *check_output_contract(bisectg256_0),

                bob_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('bob_sig', SignerType(bob_pk)),
                ('t_a', BytesType()),
                ('y', IntType()),
                ('x', IntType()),
                ('z', IntType()),
                ('t_b', BytesType()),
            ],
            next_outputs_fn=lambda args, _: [ClauseOutput(
                n=-1,
                next_contract=bisectg256_0,
                next_state=bisectg256_0.State(
                    h_start=sha256(encode_wit_element(args['x'])),
                    h_end_a=sha256(encode_wit_element(args['y'])),
                    h_end_b=sha256(encode_wit_element(args['z'])),
                    trace_a=args['t_a'],
                    trace_b=args['t_b'],
                )
            )]
        )

        super().__init__(NUMS_KEY, [withdraw, start_challenge])
