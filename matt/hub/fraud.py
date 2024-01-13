# Generic fraud proof protocol


"""
Definitions:
Let a computation for a computation trace y = f(x) be

    x = x_0 ==> x_1 ==> x_2 ==> ... ==> x_n = y

each x_i is itself a hash of something, specific to the computation.

TODO: clean up these docs, they are incoherent

where n is a power of 2 for convenience. For now, assume each step is performing exactly
the same computation, for example: double the previous element.

We know define h_i = H(x_i) for each i in 0, ..., n.

We define the trace leaves to be:
   H(h_0||h_1), H(h_1||h_2), ...
that is, a commitment to the state before the computation, and the state after.

Formally, let h_i = H(h_i || h_{i+1}) for i = 0, ..., n - 1.

From there, we can define the aggregate trace commitment for any pair i, j with i < j where j - i + 1 is a power of two:

Similarly, for any pair i, j such that j - i + 1 == 2^t >= 2
    h_{i, j} = H(x_i||x_{j+1}||h_{i, i+m-1}||h_{i+m, j}) where m = (j - i + 1)/2

We call h_{i, j; a} the value of h_{i, j} according to Alice, and h_{i, j; b} the value according to Bob.

That is, each aggregate trace commitment commits to:
  - the computation state before the leftmost leaf in the subtree is executed
  - the computation state after the rightmost leaf in the subtree is executed
  - the aggregate computation trace root for the left half
  - the aggregate computation trace root for the right half


Each internal node of the corresponds to a pair i, j with i < j, and such that j - i + 1 is a power of 2.
The "partial trace" of its node represents a computation with intermediate values
    x_i, x_{i + 1}, ..., x_j

We define the hashed state:
    h_i = sha256(x_i)     for any 0 <= i <= n

Since Alice and Bob disagree on the hashed states, we call h_{i; a} and h_{i; b} Alice's and Bob's claimed states, respectively.
    
For each 0 <= i <= j < n such that m = (j - i + 1)/2 is integer, we define the computation trace t_{i, j} as follows:

            // sha256(h_i || h_{i+1})                                       if i == j
t_{i, j} = { 
            \\ sha256(h_i || h_{i+1} || t_{i, i + m - 1} || t_{i + m, j})   otherwise

Since Alice and Bob disagree on the trace, we call t_{i, j; a} and t_{i, j; a} the traces claimed by Alice and Bob, respectively.

The entry state for an internal node of the bisection protocol contains the following info:

- The state h_i at the beginning of the computation (invariant: both parties agree)
- The state x_{j; a} at the end of the computation, according to Alice
- The state x_{j; b} at the end of the computation, according to Bob
- The root t_{i, j; a} of the computation trace in the subtree, according to Alice
- The root t_{i, j; b} of the computation trace in the subtree, according to Bob

All the bisection contracts have a forfait condition in case the other party doesn't participate; omitted for simplicity.


IF i < j, it's an internal node.
In the following, n := j - i + 1, and m = n/2. Therefore:
    The left  child of t_{i, j} is t_{i, i + m - 1}
    The right child of t_{i, j} is t_{i + m, j}

Bisect_1(alice_pk, bob_pk, i, j)[h_i, h_{j+1; a}, h_{j+1; b}, t_{i, j; a}, t_{i, j; b}]
    - Alice: reveals h_{i+m; a}, t_{i, i+m-1; a}, t_{i+m, j; a}
            (the scripts checks the equation for t_{i, j; a}
        ==> Bisect_2(*)[*, h_{i+m; a}, t_{i, i+m-1; a}, t_{i+m, j; a}]

Bisect_2(alice_pk, bob_pk, i, j)[h_i, h_{j+1; a}, h_{j+1; b}, t_{i, j; a}, t_{i, j; b}, h_{i+m; a}, t_{i, i+m-1; a}, t_{i+m, j; a}]
    - Bob: reveals h_{i+m; b}, t_{i, i+m-1; b}, t_{i+m, j; b} such that h_{i+m; a} != h_{i+m; b}   # disagree on the left child
            (the scripts checks the equation for t_{i, j; b}
        ==> Bisect_1(alice_pk, bob_pk, i, i+m-1)[h_i, h_{i+m; a}, h_{i+m; b}, t_{i, i+m-1; a}, t_{i, i+m-1; b}]
    - Bob: reveals h_{i+m; b}, t_{i, i+m-1; b}, t_{i+m, j; b} such that h_{i+m; a} == h_{i+m; b}   # disagree on the right child
            (the scripts checks the equation for t_{i, j; b}
        ==> Bisect_1(alice_pk, bob_pk, i+m, j)[x_{i+m}, x_{j+1; a}, x_{j+1; b}, h_{i+m, j; a}, h_{i+m, j; b}]

IF i == j, it's a leaf.

Leaf(alice_pk, bob_pk)[h_start, h_{end; a}, h_{end; b}]
    - Alice: reveal x_start, take the money if h_{end; a} is the hash of f(x_start)
    - Bob: reveal x_start, take the money if h_{end; b} is the hash of f(x_start)

"""


from dataclasses import dataclass
from typing import Callable, List, Tuple

from matt.merkle import MerkleTree, is_power_of_2

from .. import NUMS_KEY
from ..argtypes import ArgType, BytesType, SignerType
from ..btctools.script import OP_CAT, OP_CHECKSIG, OP_EQUAL, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_NOT, OP_PICK, OP_SHA256, OP_SWAP, OP_TOALTSTACK, OP_VERIFY, CScript
from ..contracts import ClauseOutput, StandardAugmentedP2TR, StandardClause, ContractState
from ..script_helpers import check_input_contract, check_output_contract, drop, dup, merkle_root, older


@dataclass
class Computer:
    encoder: CScript
    func: CScript
    specs: List[Tuple[str, ArgType]]


class Leaf(StandardAugmentedP2TR):
    @dataclass
    class State(ContractState):
        h_start: bytes
        h_end_alice: bytes
        h_end_bob: bytes

        def encode(self):
            return MerkleTree([self.h_start, self.h_end_alice, self.h_end_bob]).root

        def encoder_script():
            return CScript([*merkle_root(3)])

    def __init__(self, alice_pk: bytes, bob_pk: bytes, computer: Computer):
        self.alice_pk = alice_pk
        self.bob_pk = bob_pk
        self.computer = computer

        # Alice shows that she can indeed correctly perform the step
        # <alice_sig> <x...> <h_y_b>
        alice_reveal = StandardClause(
            name="alice_reveal",
            script=CScript([
                OP_TOALTSTACK,
                *dup(len(computer.specs)),

                # <alice_sig> <x...> <x...>  --  <h_y_b>

                # compute h_x
                *computer.encoder,

                OP_TOALTSTACK,

                # <alice_sig> <x...>  --  <h_y_b> <h_x>

                # compute y
                *computer.func,

                # <alice_sig> <y...>  --  <h_y_b> <h_x>

                # compute h_y
                *computer.encoder,

                # <alice_sig> <h_y>  --  <h_y_b> <h_x>

                OP_FROMALTSTACK, OP_SWAP,
                OP_FROMALTSTACK,

                # <alice_sig> <h_x> <h_y> <h_y_b>
                *merkle_root(3),
                *check_input_contract(),

                # check Alice's signature
                alice_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('alice_sig', SignerType(alice_pk)),
                *computer.specs,
                ('h_y_b', BytesType()),
            ]
        )

        # Bob shows that he can indeed correctly perform the step
        # <bob_sig> <x...> <h_y_a>
        bob_reveal = StandardClause(
            name="bob_reveal",
            script=CScript([
                OP_TOALTSTACK,
                *dup(len(computer.specs)),

                # <bob_sig> <x...> <x...>  --  <h_y_a>

                # compute h_start
                *computer.encoder,

                OP_TOALTSTACK,

                # <bob_sig> <x...>  --  <h_y_a> <h_start>

                # compute y
                *computer.func,

                # <bob_sig> <y...>  --  <h_y_a> <h_start>

                # compute h_y
                *computer.encoder,

                # <bob_sig> <h_y>  --  <h_y_a> <h_start>

                OP_FROMALTSTACK, OP_SWAP,
                OP_FROMALTSTACK, OP_SWAP,

                # <bob_sig> <h_start> <h_y_a> <h_y>
                *merkle_root(3),
                *check_input_contract(),

                # check Bob's signature
                bob_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('bob_sig', SignerType(bob_pk)),
                *computer.specs,
                ('h_y_a', BytesType()),
            ]
        )

        # a leaf does not need a forfait clause: the honest party can spend immediately

        super().__init__(NUMS_KEY, [alice_reveal, bob_reveal])


class Bisect_1(StandardAugmentedP2TR):
    @dataclass
    class State(ContractState):
        h_i: bytes
        h_j_plus_1_a: bytes
        h_j_plus_1_b: bytes
        t_i_j_a: bytes
        t_i_j_b: bytes

        def encode(self):
            return MerkleTree([
                self.h_i,
                self.h_j_plus_1_a,
                self.h_j_plus_1_b,
                self.t_i_j_a,
                self.t_i_j_b
            ]).root

        def encoder_script():
            return CScript([*merkle_root(5)])

    def __init__(self, alice_pk: bytes, bob_pk: bytes, i: int, j: int, leaf_factory: Callable[[int], Leaf], forfait_timeout: int = 10):
        self.alice_pk = alice_pk
        self.bob_pk = bob_pk
        self.i = i
        self.j = j
        self.leaf_factory = leaf_factory
        self.forfait_timeout = forfait_timeout

        assert j > i

        n = j - i + 1

        assert n >= 2 and is_power_of_2(n)

        bisect_2 = Bisect_2(alice_pk, bob_pk, i, j, leaf_factory, forfait_timeout)

        # alice reveals the children and the midstate
        # <alice_sig> <h_i> <h_j_plus_1_a>, <h_j_plus_1_b> <t_i_j_a> <t_i_j_b> <h_i_plus_m_a> <t_{i, i+m-1; a}> <t_{i+m, j; a}>
        alice_reveal = StandardClause(
            name="alice_reveal",
            script=CScript([
                OP_TOALTSTACK,
                OP_TOALTSTACK,
                OP_TOALTSTACK,

                *dup(5),

                # verify the embedded data
                *self.State.encoder_script(),
                *check_input_contract(),

                OP_FROMALTSTACK,
                OP_FROMALTSTACK,
                OP_FROMALTSTACK,

                # check equation for t_{i, j; a}:
                #     t_{i, j; a} = H(h_i||h_{j+1; a}||t_{i, i+m-1; a}||t_{i+m, j; a}) where m = (j - i + 1)/2
                # <alice_sig> <h_i> <h_j_plus_1_a>, <h_j_plus_1_b> <t_i_j_a> <t_i_j_b> <h_i_plus_m_a> <t_{i, i+m-1; a}> <t_{i+m, j; a}>
                7, OP_PICK,  # pick <h_i>
                7, OP_PICK,  # pick <h_j_plus_1_a>
                OP_CAT,
                2, OP_PICK,  # pick <t_{i, i+m-1; a}>
                OP_CAT,
                1, OP_PICK,  # pick <t_{i+m, j; a}>
                OP_CAT,
                OP_SHA256,
                5, OP_PICK,  # pick <t_i_j_a>
                OP_EQUALVERIFY,  # verify that computed and committed values for <t_i_j_a> match

                # check output
                *bisect_2.State.encoder_script(),
                *check_output_contract(bisect_2),

                alice_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('alice_sig', SignerType(alice_pk)),
                ('h_i', BytesType()),
                ('h_j_plus_1_a', BytesType()),
                ('h_j_plus_1_b', BytesType()),
                ('t_i_j_a', BytesType()),
                ('t_i_j_b', BytesType()),
                ('h_i_plus_m_a', BytesType()),
                ('t_left_a', BytesType()),
                ('t_right_a', BytesType()),
            ],
            next_outputs_fn=lambda args, _: [ClauseOutput(
                n=-1,
                next_contract=bisect_2,
                next_state=bisect_2.State(
                    h_i=args['h_i'],
                    h_j_plus_1_a=args['h_j_plus_1_a'],
                    h_j_plus_1_b=args['h_j_plus_1_b'],
                    t_i_j_a=args['t_i_j_a'],
                    t_i_j_b=args['t_i_j_b'],
                    h_i_plus_m_a=args['h_i_plus_m_a'],
                    t_left_a=args['t_left_a'],
                    t_right_a=args['t_right_a'],
                )
            )]
        )

        # Alice bailed, Bob can take the money (TODO: should burn part of it)
        forfait = StandardClause(
            name="forfait",
            script=CScript([
                *older(forfait_timeout),

                bob_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[('bob_sig', SignerType(bob_pk))]
        )

        super().__init__(NUMS_KEY, [alice_reveal, forfait])


# TODO: probably more efficient to combine the _left and _right clauses
class Bisect_2(StandardAugmentedP2TR):
    @dataclass
    class State(ContractState):
        h_i: bytes
        h_j_plus_1_a: bytes
        h_j_plus_1_b: bytes
        t_i_j_a: bytes
        t_i_j_b: bytes
        h_i_plus_m_a: bytes
        t_left_a: bytes
        t_right_a: bytes

        def encode(self):
            return MerkleTree([
                self.h_i,
                self.h_j_plus_1_a,
                self.h_j_plus_1_b,
                self.t_i_j_a,
                self.t_i_j_b,
                self.h_i_plus_m_a,
                self.t_left_a,
                self.t_right_a
            ]).root

        def encoder_script():
            return CScript([*merkle_root(8)])

    def __init__(self, alice_pk: bytes, bob_pk: bytes, i: int, j: int, leaf_factory: Callable[[int], Leaf], forfait_timeout: int = 10):
        self.alice_pk = alice_pk
        self.bob_pk = bob_pk
        self.i = i
        self.j = j
        self.leaf_factory = leaf_factory
        self.forfait_timeout = forfait_timeout

        assert j > i

        n = j - i + 1

        assert n >= 2 and is_power_of_2(n)

        m = n // 2

        are_children_leaves = m == 1

        if are_children_leaves:
            leaf_left = leaf_factory(i)
            leaf_right = leaf_factory(i + 1)
        else:
            bisect_1_left = Bisect_1(alice_pk, bob_pk, i, i + m - 1, leaf_factory, forfait_timeout)
            bisect_1_right = Bisect_1(alice_pk, bob_pk, i + m, j, leaf_factory, forfait_timeout)

        # bob reveals a midstate that doesn't match with Alice's
        # (iterate on the left child)
        # <bob_sig> <h_i> <h_j_plus_1_a>, <h_j_plus_1_b> <t_i_j_a> <t_i_j_b> <h_i_plus_m_a> <t_{i, i+m-1; a}> <t_{i+m, j; a}> <h_i_plus_m_b> <t_{i, i+m-1; b}> <t_{i+m, j; b}>
        bob_reveal_left = StandardClause(
            name="bob_reveal_left",
            script=CScript([
                OP_TOALTSTACK,
                OP_TOALTSTACK,
                OP_TOALTSTACK,

                *dup(8),

                # verify the embedded data
                *self.State.encoder_script(),
                *check_input_contract(),

                OP_FROMALTSTACK,
                OP_FROMALTSTACK,
                OP_FROMALTSTACK,

                # check equation for h_{i, j; b}:
                #     h_{i, j} = H(x_i||x_{j+1; b}||h_{i, i+m-1; b}||h_{i+m, j; b}) where m = (j - i + 1)/2
                # <bob_sig> <h_i> <h_j_plus_1_a>, <h_j_plus_1_b> <t_i_j_a> <t_i_j_b> <h_i_plus_m_a> <t_{i, i+m-1; a}> <t_{i+m, j; a}> <h_i_plus_m_b> <t_{i, i+m-1; b}> <t_{i+m, j; b}>

                10, OP_PICK,  # pick <h_i>
                9, OP_PICK,  # pick <h_j_plus_1_b>
                OP_CAT,
                2, OP_PICK,  # pick <t_{i, i+m-1; b}>
                OP_CAT,
                1, OP_PICK,  # pick <t_{i+m, j; b}>
                OP_CAT,
                OP_SHA256,
                7, OP_PICK,  # pick <t_i_j_b>
                OP_EQUALVERIFY,  # verify that computed and committed values for <t_i_j_a> match

                # check that h_{i+m; a} != h_{i+m; b}
                5, OP_PICK,
                3, OP_PICK,
                OP_EQUAL, OP_NOT, OP_VERIFY,

                # check output
                *CScript([
                    # put on top of the stack: [h_i, h_{i+m; a}, h_{i+m; b}]
                    10, OP_PICK,  # h_i
                    1 + 5, OP_PICK,
                    2 + 2, OP_PICK,
                    *leaf_left.State.encoder_script(),
                    *check_output_contract(leaf_left),
                ] if are_children_leaves else [
                    # put on top of the stack: [h_i, h_{i+m; a}, h_{i+m; b}, t_{i, i+m-1; a}, t_{i, i+m-1; b}]
                    10, OP_PICK,  # h_i
                    1 + 5, OP_PICK,
                    2 + 2, OP_PICK,
                    3 + 4, OP_PICK,
                    4 + 1, OP_PICK,
                    *bisect_1_left.State.encoder_script(),
                    *check_output_contract(bisect_1_left),
                ]),

                # only leave <bob_sig> on the stack
                *drop(11),

                bob_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('bob_sig', SignerType(bob_pk)),
                ('h_i', BytesType()),
                ('h_j_plus_1_a', BytesType()),
                ('h_j_plus_1_b', BytesType()),
                ('t_i_j_a', BytesType()),
                ('t_i_j_b', BytesType()),
                ('h_i_plus_m_a', BytesType()),
                ('t_left_a', BytesType()),
                ('t_right_a', BytesType()),
                ('h_i_plus_m_b', BytesType()),
                ('t_left_b', BytesType()),
                ('t_right_b', BytesType()),
            ],
            next_outputs_fn=lambda args, _: [ClauseOutput(
                n=-1,
                next_contract=leaf_left if are_children_leaves else bisect_1_left,
                next_state=leaf_left.State(
                    h_start=args['h_i'],
                    h_end_alice=args['h_i_plus_m_a'],
                    h_end_bob=args['h_i_plus_m_b'],
                ) if are_children_leaves else bisect_1_left.State(
                    h_i=args['h_i'],
                    h_j_plus_1_a=args['h_i_plus_m_a'],
                    h_j_plus_1_b=args['h_i_plus_m_b'],
                    t_i_j_a=args['t_left_a'],
                    t_i_j_b=args['t_left_b'],
                )
            )]
        )

        # bob reveals a midstate that matches with Alice's
        # (iterate on the right child)
        # <bob_sig> <h_i> <h_j_plus_1_a>, <h_j_plus_1_b> <t_i_j_a> <t_i_j_b> <h_i_plus_m_a> <t_{i, i+m-1; a}> <t_{i+m, j; a}> <h_i_plus_m_b> <t_{i, i+m-1; b}> <t_{i+m, j; b}>
        bob_reveal_right = StandardClause(
            name="bob_reveal_right",
            script=CScript([
                OP_TOALTSTACK,
                OP_TOALTSTACK,
                OP_TOALTSTACK,

                *dup(8),

                # verify the embedded data
                *self.State.encoder_script(),
                *check_input_contract(),

                OP_FROMALTSTACK,
                OP_FROMALTSTACK,
                OP_FROMALTSTACK,

                # check equation for t_{i, j; b}:
                #     t_{i, j} = H(h_i||h_{j+1; b}||t_{i, i+m-1; b}||t_{i+m, j; b}) where m = (j - i + 1)/2
                # <bob_sig> <h_i> <h_j_plus_1_a>, <h_j_plus_1_b> <t_i_j_a> <t_i_j_b> <h_i_plus_m_a> <t_{i, i+m-1; a}> <t_{i+m, j; a}> <h_i_plus_m_b> <t_{i, i+m-1; b}> <t_{i+m, j; b}>

                10, OP_PICK,  # pick <h_i>
                9, OP_PICK,  # pick <h_j_plus_1_b>
                OP_CAT,
                2, OP_PICK,  # pick <t_{i, i+m-1; b}>
                OP_CAT,
                1, OP_PICK,  # pick <t_{i+m, j; b}>
                OP_CAT,
                OP_SHA256,
                7, OP_PICK,  # pick <t_i_j_b>
                OP_EQUALVERIFY,  # verify that computed and committed values for <t_i_j_b> match

                # check that h_{i+m; a} == h_{i+m; b}
                5, OP_PICK,
                3, OP_PICK,
                OP_EQUALVERIFY,

                # check output
                *CScript([
                    # put on top of the stack: [h_{i+m}, h_{j+1; a}, h_{j+1; b}, t_{i+m, j; a}, t_{i+m, j; b}]
                    5, OP_PICK,
                    1 + 9, OP_PICK,
                    2 + 8, OP_PICK,
                    *leaf_right.State.encoder_script(),
                    *check_output_contract(leaf_right),
                ] if are_children_leaves else [
                    # put on top of the stack: [h_{i+m}, h_{j+1; a}, h_{j+1; b}, t_{i+m, j; a}, t_{i+m, j; b}]
                    5, OP_PICK,
                    1 + 9, OP_PICK,
                    2 + 8, OP_PICK,
                    3 + 3, OP_PICK,
                    4 + 0, OP_PICK,
                    *bisect_1_right.State.encoder_script(),
                    *check_output_contract(bisect_1_right),
                ]),

                # only leave <bob_sig> on the stack
                *drop(11),

                bob_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('bob_sig', SignerType(bob_pk)),
                ('h_i', BytesType()),
                ('h_j_plus_1_a', BytesType()),
                ('h_j_plus_1_b', BytesType()),
                ('t_i_j_a', BytesType()),
                ('t_i_j_b', BytesType()),
                ('h_i_plus_m_a', BytesType()),
                ('t_left_a', BytesType()),
                ('t_right_a', BytesType()),
                ('h_i_plus_m_b', BytesType()),
                ('t_left_b', BytesType()),
                ('t_right_b', BytesType()),
            ],
            next_outputs_fn=lambda args, _: [ClauseOutput(
                n=-1,
                next_contract=leaf_right if are_children_leaves else bisect_1_right,
                next_state=leaf_right.State(
                    h_start=args['h_i_plus_m_a'],
                    h_end_alice=args['h_j_plus_1_a'],
                    h_end_bob=args['h_j_plus_1_b'],
                ) if are_children_leaves else bisect_1_right.State(
                    h_i=args['h_i_plus_m_a'],  # this is equal to h_i_plus_m_b, as it's checked in the script!
                    h_j_plus_1_a=args['h_j_plus_1_a'],
                    h_j_plus_1_b=args['h_j_plus_1_b'],
                    t_i_j_a=args['t_right_a'],
                    t_i_j_b=args['t_right_b'],
                )
            )]
        )

        # Bob bailed, Alice can take the money (TODO: should burn part of it)
        forfait = StandardClause(
            name="forfait",
            script=CScript([
                *older(forfait_timeout),

                alice_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[('bob_sig', SignerType(bob_pk))]
        )

        super().__init__(NUMS_KEY, [[bob_reveal_left, bob_reveal_right], forfait])
