from btctools.script import OP_CHECKCONTRACTVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKTEMPLATEVERIFY, OP_DROP, OP_DUP, OP_SWAP, OP_TRUE, CScript
from matt import CCV_FLAG_CHECK_INPUT, NUMS_KEY, ClauseOutput, OpaqueP2TR, StandardClause, StandardP2TR, StandardAugmentedP2TR


class Vault(StandardP2TR):
    def __init__(self, alternate_pk: bytes | None, spend_delay: int, recover_pk: bytes, unvault_pk: bytes):
        assert (alternate_pk is None or len(alternate_pk) == 32) and len(recover_pk) == 32 and len(unvault_pk)

        self.alternate_pk = alternate_pk
        self.spend_delay = spend_delay
        self.recover_pk = recover_pk

        unvaulting = Unvaulting(alternate_pk, spend_delay, recover_pk)

        # witness: <sig> <ctv-hash> <out_i>
        trigger = StandardClause(
            name="trigger",
            script=CScript([
                # data and index already on the stack
                0 if alternate_pk is None else alternate_pk,  # pk
                unvaulting.get_taptree(),  # taptree
                0,  # standard flags
                OP_CHECKCONTRACTVERIFY,

                unvault_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('sig', bytes),
                ('ctv_hash', bytes),
                ('out_i', int),
            ],
            next_output_fn=lambda args: [ClauseOutput(n=0, next_contract=unvaulting, next_data=args['ctv_hash'])]
        )

        # witness: <out_i>
        recover = StandardClause(
            name="recover",
            script=CScript([
                0,  # data
                OP_SWAP,  # <out_i> (from witness)
                recover_pk,  # pk
                0,  # taptree
                0,  # flags
                OP_CHECKCONTRACTVERIFY,
                OP_TRUE
            ]),
            arg_specs=[
                ('out_i', int),
            ],
            next_output_fn=lambda args: [ClauseOutput(n=args['out_i'], next_contract=OpaqueP2TR(recover_pk))]
        )

        super().__init__(NUMS_KEY if alternate_pk is None else alternate_pk, [trigger, recover])


class Unvaulting(StandardAugmentedP2TR):
    def __init__(self, alternate_pk: bytes | None, spend_delay: int, recover_pk: bytes):
        assert (alternate_pk is None or len(alternate_pk) == 32) and len(recover_pk) == 32

        self.alternate_pk = alternate_pk
        self.spend_delay = spend_delay
        self.recover_pk = recover_pk

        # witness: <ctv_hash>
        withdrawal = StandardClause(
            name="withdraw",
            script=CScript([
                OP_DUP,

                # check that the top of the stack is the embedded data
                -1,  # index
                0 if alternate_pk is None else alternate_pk,  # pk
                -1,   # taptree
                CCV_FLAG_CHECK_INPUT,
                OP_CHECKCONTRACTVERIFY,

                # Check timelock
                self.spend_delay,
                OP_CHECKSEQUENCEVERIFY,
                OP_DROP,

                # Check that the transaction output is as expected
                OP_CHECKTEMPLATEVERIFY
            ]),
            arg_specs=[
                ('ctv_hash', bytes)
            ]
        )

        # witness: <out_i>
        recover = StandardClause(
            name="recover",
            script=CScript([
                0,  # data
                OP_SWAP,  # <out_i> (from witness)
                recover_pk,  # pk
                0,  # taptree
                0,  # flags
                OP_CHECKCONTRACTVERIFY,
                OP_TRUE
            ]),
            arg_specs=[
                ('out_i', int),
            ],
            next_output_fn=lambda args: [ClauseOutput(n=args['out_i'], next_contract=OpaqueP2TR(recover_pk))]
        )

        super().__init__(NUMS_KEY if alternate_pk is None else alternate_pk, [withdrawal, recover])
