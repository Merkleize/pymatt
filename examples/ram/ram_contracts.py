from matt.btctools.script import OP_CAT, OP_CHECKCONTRACTVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_DROP, OP_DUP, OP_ENDIF, OP_EQUAL, OP_FROMALTSTACK, OP_NOTIF, OP_SHA256, OP_SWAP, OP_TOALTSTACK, OP_TRUE, CScript
from matt import CCV_FLAG_CHECK_INPUT, CCV_FLAG_DEDUCT_OUTPUT_AMOUNT, NUMS_KEY, ClauseOutput, ClauseOutputAmountBehaviour, OpaqueP2TR, StandardClause, StandardP2TR, StandardAugmentedP2TR

from matt.merkle import MerkleTree, is_power_of_2, floor_lg

class RAM(StandardAugmentedP2TR):
    def __init__(self, size: int):
        assert is_power_of_2(size)

        n = floor_lg(size)

        self.n = n
        self.size = size

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
                (
                    "merkle_proof",
                    {
                        "cls": "merkleproof",
                        "depth": n
                    }
                ),
                ('merkle_root', bytes),
            ]
        )

        # witness: <out_i>
        write = StandardClause(
            name="write",
            script=CScript([
                # TODO

                0,  # data
                OP_SWAP,  # <out_i> (from witness)
                0,  # pk
                0,  # taptree
                0,  # flags
                OP_CHECKCONTRACTVERIFY,
                OP_TRUE
            ]),
            arg_specs=[
            ],
            # next_output_fn=lambda args: [ClauseOutput(n=args['out_i'], next_contract=OpaqueP2TR(recover_pk))]
        )

        super().__init__(NUMS_KEY, [withdraw, write])
