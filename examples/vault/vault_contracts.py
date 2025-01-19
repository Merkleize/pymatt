from dataclasses import dataclass
from typing import Optional

from matt import CCV_FLAG_DEDUCT_OUTPUT_AMOUNT, NUMS_KEY
from matt.argtypes import BytesType, IntType, SignerType
from matt.btctools.script import OP_CHECKCONTRACTVERIFY, OP_CHECKSIG, OP_CHECKTEMPLATEVERIFY, OP_DUP, OP_SWAP, OP_TRUE, CScript
from matt.contracts import ClauseOutput, ClauseOutputAmountBehaviour, OpaqueP2TR, StandardClause, StandardP2TR, StandardAugmentedP2TR, ContractState
from matt.script_helpers import check_input_contract, older


class Vault(StandardP2TR):
    def __init__(self, alternate_pk: Optional[bytes], spend_delay: int, recover_pk: bytes, unvault_pk: bytes, *, has_partial_revault=True, has_early_recover=True):
        assert (alternate_pk is None or len(alternate_pk) == 32) and len(recover_pk) == 32 and len(unvault_pk) == 32

        self.alternate_pk = alternate_pk
        self.spend_delay = spend_delay
        self.recover_pk = recover_pk

        unvaulting = Unvaulting(alternate_pk, spend_delay, recover_pk)

        self.has_partial_revault = has_partial_revault
        self.has_early_recover = has_early_recover

        # witness: <sig> <ctv-hash> <out_i>
        trigger = StandardClause(
            name="trigger",
            script=CScript([
                # data and index already on the stack
                0 if alternate_pk is None else alternate_pk,  # pk
                unvaulting.get_taptree_merkle_root(),  # taptree
                0,  # standard flags
                OP_CHECKCONTRACTVERIFY,

                unvault_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('sig', SignerType(unvault_pk)),
                ('ctv_hash', BytesType()),
                ('out_i', IntType()),
            ],
            next_outputs_fn=lambda args, _: [ClauseOutput(
                n=args['out_i'],
                next_contract=unvaulting,
                next_state=unvaulting.State(ctv_hash=args["ctv_hash"])
            )]
        )

        # witness: <sig> <ctv-hash> <trigger_out_i> <revault_out_i>
        trigger_and_revault = StandardClause(
            name="trigger_and_revault",
            script=CScript([
                0, OP_SWAP,   # no data tweak
                # <revault_out_i> from the witness
                -1,  # current input's taptweak
                -1,  # taptree
                CCV_FLAG_DEDUCT_OUTPUT_AMOUNT,  # revault output
                OP_CHECKCONTRACTVERIFY,

                # data and index already on the stack
                0 if alternate_pk is None else alternate_pk,  # pk
                unvaulting.get_taptree_merkle_root(),  # taptree
                0,  # standard flags
                OP_CHECKCONTRACTVERIFY,

                unvault_pk,
                OP_CHECKSIG
            ]),
            arg_specs=[
                ('sig', SignerType(unvault_pk)),
                ('ctv_hash', BytesType()),
                ('out_i', IntType()),
                ('revault_out_i', IntType()),
            ],
            next_outputs_fn=lambda args, _: [
                ClauseOutput(n=args['revault_out_i'], next_contract=self,
                             next_amount=ClauseOutputAmountBehaviour.DEDUCT_OUTPUT),
                ClauseOutput(
                    n=args['out_i'],
                    next_contract=unvaulting,
                    next_state=unvaulting.State(ctv_hash=args["ctv_hash"])),
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
                ('out_i', IntType()),
            ],
            next_outputs_fn=lambda args, _: [ClauseOutput(n=args['out_i'], next_contract=OpaqueP2TR(recover_pk))]
        )

        if self.has_partial_revault:
            if self.has_early_recover:
                clauses = [trigger, [trigger_and_revault, recover]]
            else:
                clauses = [trigger, trigger_and_revault]
        else:
            if self.has_early_recover:
                clauses = [trigger, recover]
            else:
                clauses = trigger

        super().__init__(NUMS_KEY if alternate_pk is None else alternate_pk, clauses)


class Unvaulting(StandardAugmentedP2TR):
    @dataclass
    class State(ContractState):
        ctv_hash: bytes

        def encode(self):
            return self.ctv_hash

        def encoder_script():
            return CScript([])

    def __init__(self, alternate_pk: Optional[bytes], spend_delay: int, recover_pk: bytes):
        assert (alternate_pk is None or len(alternate_pk) == 32) and len(recover_pk) == 32

        self.alternate_pk = alternate_pk
        self.spend_delay = spend_delay
        self.recover_pk = recover_pk

        # witness: <ctv_hash>
        withdrawal = StandardClause(
            name="withdraw",
            script=CScript([
                OP_DUP,

                *check_input_contract(-1, alternate_pk),

                # Check timelock
                *older(self.spend_delay),

                # Check that the transaction output is as expected
                OP_CHECKTEMPLATEVERIFY
            ]),
            arg_specs=[
                ('ctv_hash', BytesType())
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
                ('out_i', IntType()),
            ],
            next_outputs_fn=lambda args, _: [ClauseOutput(n=args['out_i'], next_contract=OpaqueP2TR(recover_pk))]
        )

        super().__init__(NUMS_KEY if alternate_pk is None else alternate_pk, [withdrawal, recover])
