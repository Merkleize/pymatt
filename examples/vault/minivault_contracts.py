from dataclasses import dataclass
from typing import Optional

from matt import CCV_FLAG_DEDUCT_OUTPUT_AMOUNT, NUMS_KEY
from matt.argtypes import BytesType, IntType, SignerType
from matt.btctools.script import OP_CHECKCONTRACTVERIFY, OP_CHECKSIG, OP_DUP, OP_PICK, OP_SWAP, OP_TRUE, CScript
from matt.contracts import ClauseOutput, ClauseOutputAmountBehaviour, OpaqueP2TR, StandardClause, StandardAugmentedP2TR, ContractState
from matt.script_helpers import check_input_contract, older


class Vault(StandardAugmentedP2TR):
    State = None  # Stateless contract

    def __init__(self, alternate_pk: Optional[bytes], spend_delay: int, recover_pk: bytes, unvault_pk: bytes, *, has_partial_revault=True, has_early_recover=True):
        assert (alternate_pk is None or len(alternate_pk) == 32) and len(recover_pk) == 32 and len(unvault_pk) == 32

        self.alternate_pk = alternate_pk
        self.spend_delay = spend_delay
        self.recover_pk = recover_pk

        unvaulting = Unvaulting(alternate_pk, spend_delay, recover_pk)

        self.has_partial_revault = has_partial_revault
        self.has_early_recover = has_early_recover

        # witness: <sig> <withdrawal_pk> <out_i>
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
                ('withdrawal_pk', BytesType()),
                ('out_i', IntType()),
            ],
            next_outputs_fn=lambda args, _: [ClauseOutput(
                n=args['out_i'],
                next_contract=unvaulting,
                next_state=unvaulting.State(withdrawal_pk=args["withdrawal_pk"])
            )]
        )

        # witness: <sig> <withdrawal_pk> <trigger_out_i> <revault_out_i>
        trigger_and_revault = StandardClause(
            name="trigger_and_revault",
            script=CScript([
                0, OP_SWAP,   # no data tweak
                # <revault_out_i> from the witness
                -1,  # current input's internal key
                -1,  # current input's taptweak
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
                ('withdrawal_pk', BytesType()),
                ('out_i', IntType()),
                ('revault_out_i', IntType()),
            ],
            next_outputs_fn=lambda args, _: [
                ClauseOutput(n=args['revault_out_i'], next_contract=self,
                             next_amount=ClauseOutputAmountBehaviour.DEDUCT_OUTPUT),
                ClauseOutput(
                    n=args['out_i'],
                    next_contract=unvaulting,
                    next_state=unvaulting.State(withdrawal_pk=args["withdrawal_pk"])),
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
        withdrawal_pk: bytes

        def encode(self):
            return self.withdrawal_pk

        def encoder_script():
            return CScript([])

    def __init__(self, alternate_pk: Optional[bytes], spend_delay: int, recover_pk: bytes):
        assert (alternate_pk is None or len(alternate_pk) == 32) and len(recover_pk) == 32

        self.alternate_pk = alternate_pk
        self.spend_delay = spend_delay
        self.recover_pk = recover_pk

        # witness: <withdrawal_pk>
        withdrawal = StandardClause(
            name="withdraw",
            script=CScript([
                OP_DUP,

                *check_input_contract(-1, alternate_pk),

                # Check timelock
                *older(self.spend_delay),

                # Check that the transaction output is as expected
                0,  # no data
                0,  # output index
                2, OP_PICK,  # withdrawal_pk
                0,  # no taptweak
                0,  # default flags
                OP_CHECKCONTRACTVERIFY,

                # withdrawal_pk is left on the stack on success
            ]),
            arg_specs=[
                ('withdrawal_pk', BytesType())
            ],
            next_outputs_fn=lambda args, _: [ClauseOutput(n=0, next_contract=OpaqueP2TR(args['withdrawal_pk']))]
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
