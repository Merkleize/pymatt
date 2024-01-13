from dataclasses import dataclass
from typing import List

from matt import CCV_FLAG_CHECK_INPUT, NUMS_KEY
from matt.argtypes import BytesType, MerkleProofType
from matt.btctools.script import OP_CAT, OP_CHECKCONTRACTVERIFY, OP_DUP, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_IF, OP_NOTIF, OP_PICK, OP_ROLL, OP_ROT, OP_SHA256, OP_SWAP, OP_TOALTSTACK, OP_TRUE, CScript
from matt.contracts import ClauseOutput, StandardClause, StandardAugmentedP2TR, ContractState
from matt.merkle import MerkleTree, is_power_of_2, floor_lg
from matt.script_helpers import merkle_root


class RAM(StandardAugmentedP2TR):
    @dataclass
    class State(ContractState):
        leaves: List[bytes]

        def encode(self):
            return MerkleTree(self.leaves).root

        def encoder_script(size: int):
            return merkle_root(size)

    def __init__(self, size: int):
        assert is_power_of_2(size)

        self.size = size

        n = floor_lg(size)
        self.n = n

        # witness: <h_1> <d_1> <h_2> <d_2> ... <h_n> <d_n> <x> <root>
        withdraw = StandardClause(
            name="withdraw",
            script=CScript([
                OP_DUP,
                OP_TOALTSTACK,

                # check that the top of the stack is the embedded data
                -1,  # index
                0,   # pk
                -1,  # taptree
                CCV_FLAG_CHECK_INPUT,
                OP_CHECKCONTRACTVERIFY,

                # stack: <h_1> <d_1> <h_2> <d_2> ... <h_n> <d_n> <x>
                # alt  : <root>

                # repeat until the root is computed
                # TODO: we could save an opcode by modifying the order of witness elements
                *([
                    OP_SWAP,  # put direction on top
                    # TODO: should we check that it's either exactly 0 or exactly 1?

                    OP_NOTIF,
                    # left child; swap, as we want x || h_i
                    OP_SWAP,
                    OP_ENDIF,

                    OP_CAT,
                    OP_SHA256
                ] * n),

                OP_FROMALTSTACK,
                OP_EQUAL
            ]),
            arg_specs=[
                ("merkle_proof", MerkleProofType(n)),
                ('merkle_root', BytesType()),
            ]
        )

        def next_outputs_fn(args: dict, state: RAM.State):
            i: int = args["merkle_proof"].get_leaf_index()

            return [
                ClauseOutput(
                    n=-1,
                    next_contract=self,
                    next_state=self.State(
                        leaves=state.leaves[:i] + [args["new_value"]] + state.leaves[i+1:]
                    )
                )
            ]

        # witness: <h_1> <d_1> <h_2> <d_2> ... <h_n> <d_n> <x_old> <x_new> <root>
        write = StandardClause(
            name="write",
            script=CScript([
                OP_DUP,
                OP_TOALTSTACK,

                # stack: <h_1> <d_1> <h_2> <d_2> ... <h_n> <d_n> <x_old> <x_new> <root>
                # alt  : <root>

                # check that the top of the stack is the embedded data
                -1,  # index
                0,   # pk
                -1,  # taptree
                CCV_FLAG_CHECK_INPUT,
                OP_CHECKCONTRACTVERIFY,

                # stack: <h_1> <d_1> <h_2> <d_2> ... <h_n> <d_n> <x_old> <x_new>
                # alt  : <root>

                # repeat until both the old and new roots are computed
                *([
                    2, OP_ROLL,  # put direction on top

                    # TODO: should we check that the direction is either exactly 0 or exactly 1?

                    # TODO: seems too verbose, there should be a way of optimizing it
                    # top of stack is now: <h> <x_old> <x_new> <d>
                    OP_IF,
                    # top of stack is now: <h> <x_old> <x_new>
                    # right child: we want h || x
                    2, OP_PICK,
                    # top of stack is now: <h> <x_old> <x_new> <h>
                    OP_SWAP,
                    OP_CAT,
                    OP_SHA256,
                    # top of stack is now: <h> <x_old> <SHA(h || x_new)>

                    OP_SWAP,
                    # top of stack is now: <h> <SHA(h || x_new)> <x_old>
                    OP_ROT,
                    # top of stack is now: <SHA(h || x_new)> <x_old> <h>
                    OP_SWAP,
                    # OP_CAT,
                    # OP_SHA256,
                    # # top of stack is now: <SHA(h || x_new)> <SHA(h || x_old)>

                    # OP_SWAP,
                    # # top of stack is now: <SHA(h || x_old)> <SHA(h || x_new)>
                    OP_ELSE,
                    # top of stack is now: <h> <x_old> <x_new>
                    2, OP_PICK,
                    # top of stack is now: <h> <x_old> <x_new> <h>
                    OP_CAT,
                    OP_SHA256,
                    # top of stack is now: <h> <x_old> <SHA(x_new || h)>

                    OP_SWAP,
                    OP_ROT,
                    # top of stack is now: <SHA(x_new || h)> <x_old> <h>

                    # OP_CAT,
                    # OP_SHA256,
                    # # top of stack is now: <SHA(x_new || h)> <SHA(x_old || h)>

                    # OP_SWAP,
                    # # top of stack is now: <SHA(x_old || h)> <SHA(x_new || h)>
                    OP_ENDIF,

                    # this is in common between the two branches, so we can put it here
                    OP_CAT,
                    OP_SHA256,
                    OP_SWAP,

                ] * n),

                # stack: <old_root> <new_root>
                # alt  : <root>

                # check that ineed old_root_computed == root as expected
                OP_SWAP,
                OP_FROMALTSTACK,
                OP_EQUALVERIFY,

                # stack: <new_root>

                # Check that new_root is committed in the next output,
                -1,  # index
                0,   # NUMS
                -1,  # keep current taptree
                0,   # default, preserve amount
                OP_CHECKCONTRACTVERIFY,

                OP_TRUE
            ]),
            arg_specs=[
                ("merkle_proof", MerkleProofType(n)),
                # the new value of the element (its index is specified by the directions in the merkle proof)
                ('new_value', BytesType()),
                ('merkle_root', BytesType()),
            ],
            next_outputs_fn=next_outputs_fn
        )

        super().__init__(NUMS_KEY, [withdraw, write])
