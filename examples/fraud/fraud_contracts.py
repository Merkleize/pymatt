

from matt import NUMS_KEY
from matt.argtypes import BytesType, IntType, SignerType
from matt.btctools.common import sha256
from matt.btctools.script import OP_ADD, OP_CHECKSIG, OP_DUP, OP_FROMALTSTACK, OP_ROT, OP_SHA256, OP_SWAP, OP_TOALTSTACK, CScript
from matt.contracts import ClauseOutput, StandardClause, StandardAugmentedP2TR, StandardP2TR
from matt.hub.fraud import Bisect_1, Computer, Leaf
from matt.merkle import MerkleTree
from matt.script_helpers import check_input_contract, check_output_contract, drop, dup, merkle_root, older
from matt.utils import encode_wit_element


# TODO: add forfait clauses whenever needed

# TODO: how to generalize what the contract does after the leaf? We should be able to compose clauses with some external code.
#       Do we need "clause" algebra?

# TODO: Augmented contracts should also specify the "encoder" for its data, so that callers don't have to worry
#       about handling Merkle trees by hand.
#       Might also be needed to define "higher order contracts" that can be used as a gadget, then provide a result
#       to some other contract provided by the caller.

class G256_S0(StandardP2TR):
    def __init__(self, alice_pk: bytes, bob_pk: bytes, forfait_timeout: int = 10):
        self.alice_pk = alice_pk
        self.bob_pk = bob_pk
        self.forfait_timeout = forfait_timeout

        # witness: <bob_sig> <x>
        choose = StandardClause(
            name="choose",
            script=CScript([
                OP_SHA256,  # sha256(x)
                *check_output_contract(G256_S1(alice_pk, bob_pk, forfait_timeout)),

                bob_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('bob_sig', SignerType(bob_pk)),
                ('x', IntType()),
            ],
            next_output_fn=lambda args: [ClauseOutput(
                n=-1,
                next_contract=G256_S1(alice_pk, bob_pk, forfait_timeout),
                next_data=sha256(encode_wit_element(args['x']))
            )]
        )

        super().__init__(NUMS_KEY, choose)


class G256_S1(StandardAugmentedP2TR):
    def __init__(self, alice_pk: bytes, bob_pk: bytes, forfait_timeout):
        self.alice_pk = alice_pk
        self.bob_pk = bob_pk
        self.forfait_timeout = forfait_timeout

        g256_s2 = G256_S2(alice_pk, bob_pk, forfait_timeout)

        # reveal: <alice_sig> <r_a> <y> <sha256(x)>
        reveal = StandardClause(
            name="reveal",
            script=CScript([
                OP_DUP,

                # check that the top of the stack is the embedded data
                *check_input_contract(),

                OP_TOALTSTACK,
                OP_SHA256,
                OP_FROMALTSTACK,

                # <alice_sig> <t_a> <sha256(y)> <sha256(x)>
                *merkle_root(3),

                # <alice_sig> <merkle_root(t_a, sha256(y), sha256(x))>

                *check_output_contract(g256_s2),

                alice_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('alice_sig', SignerType(alice_pk)),
                ('t_a', BytesType()),
                ('y', IntType()),
                ('sha256_x', BytesType()),
            ],
            next_output_fn=lambda args: [ClauseOutput(
                n=-1,
                next_contract=g256_s2,
                next_data=MerkleTree([args['t_a'], sha256(encode_wit_element(args['y'])), args['sha256_x']]).root
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
        # start_challenge: <bob_sig> <t_a> <sha256(y)> <sha256(x)> <z> <t_b>
        start_challenge = StandardClause(
            name="start_challenge",
            script=CScript([
                OP_TOALTSTACK,
                OP_SHA256, OP_TOALTSTACK,

                # <bob_sig> <t_a> <sha256(y)> <sha256(x)>  ---  <t_b> <sha256(z)>

                # verify the embedded data
                *dup(3),
                *merkle_root(3),
                *check_input_contract(),

                # <bob_sig> <t_a> <sha256(y)> <sha256(x)>  ---  <t_b> <sha256(z)>
                OP_SWAP,
                # <bob_sig> <t_a> <sha256(x)> <sha256(y)>  ---  <t_b> <sha256(z)>
                OP_ROT,
                # <bob_sig> <sha256(x)> <sha256(y)> <t_a>  ---  <t_b> <sha256(z)>

                OP_FROMALTSTACK,
                # <bob_sig> <sha256(x)> <sha256(y)> <t_a> <sha256(z)>  ---  <t_b>
                OP_SWAP,
                # <bob_sig> <sha256(x)> <sha256(y)> <sha256(z)> <t_a>  ---  <t_b>

                OP_FROMALTSTACK,

                # <bob_sig> <sha256(x)> <sha256(y)> <sha256(z)> <t_a> <t_b>

                *merkle_root(5),
                *check_output_contract(bisectg256_0),

                bob_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('bob_sig', SignerType(bob_pk)),
                ('t_a', BytesType()),
                ('sha256_y', BytesType()),
                ('sha256_x', BytesType()),
                ('z', IntType()),
                ('t_b', BytesType()),
            ],
            next_output_fn=lambda args: [ClauseOutput(
                n=-1,
                next_contract=bisectg256_0,
                next_data=MerkleTree([
                    args['sha256_x'],
                    args['sha256_y'],
                    sha256(encode_wit_element(args['z'])),
                    args['t_a'],
                    args['t_b'],
                ]).root
            )]
        )

        super().__init__(NUMS_KEY, [withdraw, start_challenge])
