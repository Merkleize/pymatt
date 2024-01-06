

from matt import NUMS_KEY
from matt.argtypes import BytesType, IntType, SignerType
from matt.btctools.common import sha256
from matt.btctools.script import OP_2DROP, OP_ADD, OP_CAT, OP_CHECKSIG, OP_DROP, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_NOT, OP_PICK, OP_ROT, OP_SHA256, OP_SWAP, OP_TOALTSTACK, OP_VERIFY, CScript
from matt.contracts import ClauseOutput, StandardClause, StandardAugmentedP2TR, StandardP2TR
from matt.merkle import MerkleTree, is_power_of_2
from matt.script_helpers import check_input_contract, check_output_contract, dup, merkle_root, older
from matt.utils import encode_wit_element


"""
Definitions:
Let a computation for a computation trace y = f(x) be

    x = x_0 ==> x_1 ==> x_2 ==> ... ==> x_n = y

each x_i is itself a hash of something, specific to the computation.
TODO: might be cleaner to call x_i the unhashed state, and give a name to its commitment.
      Currently, x_i itself is a commitment to the state.

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

This is all the definitions we need.


Contracts:

   G256_S0(alice_pk, bob_pk): Bob chooses x
   G256_S1(alice_pk, bob_pk)[x]: Alice publishes y (that should be 256 * x), and the computation trace root r_a
   G256_S2(alice_pk, bob_pk)[x, y, r_a]:
      - after 1 day: Alice takes the money
      - Bob disagrees and publishes his answer z and trace root r_b

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

   BisectG256_0(alice_pk, bob_pk, i, j)[h_i, h_{j+1; a}, h_{j+1; b}, t_{i, j; a}, t_{i, j; b}]
       - Alice: reveals h_{i+m; a}, t_{i, i+m-1; a}, t_{i+m, j; a}
                (the scripts checks the equation for t_{i, j; a}
         ==> BisectG256_1(*)[*, h_{i+m; a}, t_{i, i+m-1; a}, t_{i+m, j; a}]

   BisectG256_1(alice_pk, bob_pk, i, j)[h_i, h_{j+1; a}, h_{j+1; b}, t_{i, j; a}, t_{i, j; b}, h_{i+m; a}, t_{i, i+m-1; a}, t_{i+m, j; a}]
       - Bob: reveals h_{i+m; b}, t_{i, i+m-1; b}, t_{i+m, j; b} such that h_{i+m; a} != h_{i+m; b}   # disagree on the left child
              (the scripts checks the equation for t_{i, j; b}
         ==> BisectG256_0(alice_pk, bob_pk, i, i+m-1)[h_i, h_{i+m; a}, h_{i+m; b}, t_{i, i+m-1; a}, t_{i, i+m-1; b}]
       - Bob: reveals h_{i+m; b}, t_{i, i+m-1; b}, t_{i+m, j; b} such that h_{i+m; a} == h_{i+m; b}   # disagree on the right child
              (the scripts checks the equation for t_{i, j; b}
         ==> BisectG256_0(alice_pk, bob_pk, i+m, j)[x_{i+m}, x_{j+1; a}, x_{j+1; b}, h_{i+m, j; a}, h_{i+m, j; b}]

   IF i == j, it's a leaf.

   Leaf(alice_pk, bob_pk)[h_start, h_{end; a}, h_{end; b}]
       - Alice: reveal x_start, take the money if h_{end; a} is the hash of f(x_start)
       - Bob: reveal x_start, take the money if h_{end; b} is the hash of f(x_start)

"""


# TODO: add forfait clauses whenever needed

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
                n=0,
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
                n=0,
                next_contract=g256_s2,
                next_data=MerkleTree([args['t_a'], sha256(encode_wit_element(args['y'])), args['sha256_x']]).root
            )]
        )

        super().__init__(NUMS_KEY, reveal)


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

        bisectg256_0 = BisectG256_0(alice_pk, bob_pk, 0, 7, forfait_timeout)
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
                n=0,
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


# Fraud proof protocol from here

class BisectG256_0(StandardAugmentedP2TR):
    def __init__(self, alice_pk: bytes, bob_pk: bytes, i: int, j: int, forfait_timeout: int = 10):
        self.alice_pk = alice_pk
        self.bob_pk = bob_pk
        self.i = i
        self.j = j
        self.forfait_timeout = forfait_timeout

        assert j > i

        n = j - i + 1

        assert n >= 2 and is_power_of_2(n)

        bisectg256_1 = BisectG256_1(alice_pk, bob_pk, i, j, forfait_timeout)

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
                *merkle_root(5),
                *check_input_contract(),

                OP_FROMALTSTACK,
                OP_FROMALTSTACK,
                OP_FROMALTSTACK,

                # check equation for t_{i, j; a}:
                #     t_{i, j; a} = H(h_i||h_{j+1; a}||h_{i, i+m-1; a}||h_{i+m, j; a}) where m = (j - i + 1)/2
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

                *merkle_root(8),
                *check_output_contract(bisectg256_1),

                alice_pk,
                OP_CHECKSIG  # TODO: maybe this is not needed, hashes are not malleable anyway
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
            next_output_fn=lambda args: [ClauseOutput(
                n=0,
                next_contract=bisectg256_1,
                next_data=MerkleTree([
                    args['h_i'],
                    args['h_j_plus_1_a'],
                    args['h_j_plus_1_b'],
                    args['t_i_j_a'],
                    args['t_i_j_b'],
                    args['h_i_plus_m_a'],
                    args['t_left_a'],
                    args['t_right_a'],
                ]).root
            )]
        )

        super().__init__(NUMS_KEY, alice_reveal)


class BisectG256_1(StandardAugmentedP2TR):
    def __init__(self, alice_pk: bytes, bob_pk: bytes, i: int, j: int, forfait_timeout: int = 10):
        self.alice_pk = alice_pk
        self.bob_pk = bob_pk
        self.i = i
        self.j = j
        self.forfait_timeout = forfait_timeout

        assert j > i

        n = j - i + 1

        assert n >= 2 and is_power_of_2(n)

        m = n // 2

        are_children_leaves = m == 1

        if are_children_leaves:
            leaf = Leaf2x(alice_pk, bob_pk)
        else:
            bisectg256_0_left = BisectG256_0(alice_pk, bob_pk, i, i + m - 1, forfait_timeout)
            bisectg256_0_right = BisectG256_0(alice_pk, bob_pk, i + m, j, forfait_timeout)

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
                *merkle_root(8),
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
                    *merkle_root(3),
                    *check_output_contract(leaf),
                ] if are_children_leaves else [
                    # put on top of the stack: [h_i, h_{i+m; a}, h_{i+m; b}, t_{i, i+m-1; a}, t_{i, i+m-1; b}]
                    10, OP_PICK,  # h_i
                    1 + 5, OP_PICK,
                    2 + 2, OP_PICK,
                    3 + 4, OP_PICK,
                    4 + 1, OP_PICK,
                    *merkle_root(5),
                    *check_output_contract(bisectg256_0_left),
                ]),

                # drop 11 stack elements (only leave <bob_sig>)
                OP_2DROP, OP_2DROP, OP_2DROP, OP_2DROP, OP_2DROP, OP_DROP,

                bob_pk,
                OP_CHECKSIG  # TODO: maybe this is not needed, hashes are not malleable anyway
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
            next_output_fn=lambda args: [ClauseOutput(
                n=0,
                next_contract=leaf if are_children_leaves else bisectg256_0_left,
                next_data=MerkleTree([
                    args['h_i'],
                    args['h_i_plus_m_a'],
                    args['h_i_plus_m_b'],
                ]).root if are_children_leaves else MerkleTree([
                    args['h_i'],
                    args['h_i_plus_m_a'],
                    args['h_i_plus_m_b'],
                    args['t_left_a'],
                    args['t_left_b'],
                ]).root
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
                *merkle_root(8),
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
                    *merkle_root(3),
                    *check_output_contract(leaf),
                ] if are_children_leaves else [
                    # put on top of the stack: [h_{i+m}, h_{j+1; a}, h_{j+1; b}, t_{i+m, j; a}, t_{i+m, j; b}]
                    5, OP_PICK,
                    1 + 9, OP_PICK,
                    2 + 8, OP_PICK,
                    3 + 3, OP_PICK,
                    4 + 0, OP_PICK,
                    *merkle_root(5),
                    *check_output_contract(bisectg256_0_right),
                ]),

                # drop 11 stack elements (only leave <bob_sig>)
                OP_2DROP, OP_2DROP, OP_2DROP, OP_2DROP, OP_2DROP, OP_DROP,

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
            next_output_fn=lambda args: [ClauseOutput(
                n=0,
                next_contract=leaf if are_children_leaves else bisectg256_0_right,
                next_data=MerkleTree([
                    args['h_i_plus_m_a'],
                    args['h_j_plus_1_a'],
                    args['h_j_plus_1_b'],
                ]).root if are_children_leaves else MerkleTree([
                    args['h_i_plus_m_a'],  # this is equal to h_i_plus_m_b, as it's checked in the script!
                    args['h_j_plus_1_a'],
                    args['h_j_plus_1_b'],
                    args['t_right_a'],
                    args['t_right_b'],
                ]).root
            )]
        )

        super().__init__(NUMS_KEY, [bob_reveal_left, bob_reveal_right])


# h_start, h_{end; a}, h_{end; b}
class Leaf2x(StandardAugmentedP2TR):
    def __init__(self, alice_pk: bytes, bob_pk: bytes):
        self.alice_pk = alice_pk
        self.bob_pk = bob_pk

        # Alice shows that she can indeed correctly perform the step
        # <alice_sig> <x_start> <h_{end; b}>
        alice_reveal = StandardClause(
            name="alice_reveal",
            script=CScript([
                OP_TOALTSTACK,
                OP_DUP,

                # <alice_sig> <x_start> <x_start>  --  <h_{end; b}>

                # compute h_start
                OP_SHA256,
                OP_TOALTSTACK,

                # <alice_sig> <x_start>  --  <h_{end; b}> <h_start>

                # compute x_end
                OP_DUP, OP_ADD,

                # <alice_sig> <x_end>  --  <h_{end; b}> <h_start>

                # compute h_end
                OP_SHA256,

                # <alice_sig> <h_end>  --  <h_{end; b}> <h_start>

                OP_FROMALTSTACK, OP_SWAP,
                OP_FROMALTSTACK,

                *merkle_root(3),
                *check_input_contract(),

                # check Alice's signature
                alice_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('alice_sig', SignerType(alice_pk)),
                ('x_start', IntType()),
                ('h_end_b', BytesType()),
            ]
        )

        # Bob shows that she can indeed correctly perform the step
        # <bob_sig> <x_start> <h_{end; a}>
        bob_reveal = StandardClause(
            name="bob_reveal",
            script=CScript([
                OP_TOALTSTACK,
                OP_DUP,

                # <alice_sig> <x_start> <x_start>  --  <h_{end; a}>

                # compute h_start
                OP_SHA256,
                OP_TOALTSTACK,

                # <alice_sig> <x_start>  --  <h_{end; a}> <h_start>

                # compute x_end
                OP_DUP, OP_ADD,

                # <alice_sig> <x_end>  --  <h_{end; a}> <h_start>

                # compute h_end
                OP_SHA256,

                # <alice_sig> <h_end>  --  <h_{end; a}> <h_start>

                OP_FROMALTSTACK, OP_SWAP,
                OP_FROMALTSTACK, OP_SWAP,

                *merkle_root(3),
                *check_input_contract(),

                # check Bob's signature
                bob_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('bob_sig', SignerType(bob_pk)),
                ('x_start', IntType()),
                ('h_end_a', BytesType()),
            ]
        )

        super().__init__(NUMS_KEY, [alice_reveal, bob_reveal])
