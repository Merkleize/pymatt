from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from typing import Callable

from .argtypes import ArgType
from .btctools import script, key
from .btctools.auth_proxy import AuthServiceProxy
from .btctools.messages import COutPoint, CTransaction, CTxIn, CTxInWitness
from .btctools.script import OP_1, CScript, CTxOut, TaprootInfo
from .btctools.segwit_addr import encode_segwit_address
from .utils import wait_for_output, wait_for_spending_tx

# Flags for OP_CHECKCONTRACTVERIFY
CCV_FLAG_CHECK_INPUT: int = -1
CCV_FLAG_IGNORE_OUTPUT_AMOUNT: int = 1
CCV_FLAG_DEDUCT_OUTPUT_AMOUNT: int = 2

# point with provably unknown private key
NUMS_KEY: bytes = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


class AbstractContract:
    pass


class ClauseOutputAmountBehaviour(Enum):
    PRESERVE_OUTPUT = 0  # The output should be at least as large as the input
    IGNORE_OUTPUT = 1  # The output amount is not checked
    DEDUCT_OUTPUT = 1  # The output amount is subtracted from the input


@dataclass
class ClauseOutput:
    n: None | int
    next_contract: AbstractContract  # only StandardP2TR and StandardAugmentedP2TR are supported so far
    next_data: None | bytes = None  # only meaningful if c is augmented
    next_amount: ClauseOutputAmountBehaviour = ClauseOutputAmountBehaviour.PRESERVE_OUTPUT

    def __repr__(self):
        return f"ClauseOutput(n={self.n}, next_contract={self.next_contract}, next_data={self.next_data}, next_amount={self.next_amount})"


class Clause:
    def __init__(self, name: str, script: CScript):
        self.name = name
        self.script = script

    def stack_elements_from_args(self, args: dict) -> list[bytes]:
        raise NotImplementedError

    def next_outputs(self, args: dict) -> list[ClauseOutput]:
        raise NotImplementedError

    def args_from_stack_elements(self, elements: list[bytes]) -> dict:
        raise NotImplementedError

    def __repr__(self):
        return f"<Clause(name={self.name}, script={self.script})>"


# A StandardClause encodes simple scripts where the witness is exactly
# a list of arguments, always in the same order, and each is either
# an integer or a byte array.
# Other types of generic treatable clauses could be defined (for example, a MiniscriptClause).
# Moreover, it specifies a function that converts the arguments of the clause, to the data of the next output.
class StandardClause(Clause):
    def __init__(self, name: str, script: CScript, arg_specs: list[tuple[str, ArgType]], next_output_fn: Callable[[dict], list[ClauseOutput] | CTransaction] | None = None):
        super().__init__(name, script)
        self.arg_specs = arg_specs

        self.next_outputs_fn = next_output_fn



    def next_outputs(self, args: dict) -> list[ClauseOutput] | CTransaction:
        if self.next_outputs_fn is not None:
            return self.next_outputs_fn(args)
        else:
            return []

    def stack_elements_from_args(self, args: dict) -> list[bytes]:
        result: list[bytes] = []
        for arg_name, arg_cls in self.arg_specs:
            if arg_name not in args:
                raise ValueError(f"Missing argument: {arg_name}")
            arg_value = args[arg_name]

            result.extend(arg_cls.serialize_to_wit(arg_value))

        return result

    def args_from_stack_elements(self, elements: list[bytes]) -> dict:
        result = {}
        cur = 0
        for arg_name, arg_cls in self.arg_specs:
            if cur >= len(elements):
                raise ValueError("Too few elements to decode")

            n_consumed, value = arg_cls.deserialize_from_wit(elements[cur:])
            result[arg_name] = value
            cur += n_consumed

        if cur != len(elements):
            raise ValueError("Too many elements to decode")

        return result

    def __repr__(self):
        return f"{self.__class__.__name__}(name={self.name})"


class OpaqueP2TR(AbstractContract):
    """
    A class representing a Pay-to-Taproot script, where only the final pubkey is known.
    """

    def __init__(self, pubkey: bytes):
        assert len(pubkey) == 32

        self.pubkey = pubkey
        # Skip the tweak if there are no scripts
        # Note that this is different than BIP-86, where the key is tweaked with an unspendable script tree hash
        self.tr_info = TaprootInfo(CScript([OP_1, pubkey]), pubkey, None, None, {}, None, pubkey, 0)

    def get_tr_info(self) -> TaprootInfo:
        return self.tr_info

    def get_address(self) -> str:
        return encode_segwit_address("bcrt", 1, bytes(self.get_tr_info().scriptPubKey)[2:])

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(pubkey={self.pubkey.hex()})"


class P2TR(AbstractContract):
    """
    A class representing a Pay-to-Taproot script.
    """

    def __init__(self, internal_pubkey: bytes, scripts: list[tuple[str, CScript]]):
        assert len(internal_pubkey) == 32

        self.internal_pubkey = internal_pubkey
        self.scripts = scripts
        self.tr_info = script.taproot_construct(internal_pubkey, scripts)

    def get_tr_info(self) -> TaprootInfo:
        return self.tr_info

    def get_address(self) -> str:
        return encode_segwit_address("bcrt", 1, bytes(self.get_tr_info().scriptPubKey)[2:])

    def __repr__(self):
        return f"{self.__class__.__name__}(internal_pubkey={self.internal_pubkey.hex()})"


class AugmentedP2TR(AbstractContract):
    """
    An abstract class representing a Pay-to-Taproot script with some embedded data.
    While the exact script can only be produced once the embedded data is known,
    the scripts and the "naked internal key" are decided in advance.
    """

    def __init__(self, naked_internal_pubkey: bytes):
        assert len(naked_internal_pubkey) == 32

        self.naked_internal_pubkey = naked_internal_pubkey

    def get_scripts(self) -> list[tuple[str, CScript]]:
        raise NotImplementedError("This must be implemented in subclasses")

    def get_taptree(self) -> bytes:
        # use dummy data, since it doesn't affect the merkle root
        return self.get_tr_info(b'\0'*32).merkle_root

    def get_tr_info(self, data: bytes) -> TaprootInfo:
        assert len(data) == 32

        internal_pubkey, _ = key.tweak_add_pubkey(self.naked_internal_pubkey, data)

        return script.taproot_construct(internal_pubkey, self.get_scripts())

    def __repr__(self):
        return f"{self.__class__.__name__}(naked_internal_pubkey={self.naked_internal_pubkey.hex()}. Contracts's data: {self.data})"


class StandardP2TR(P2TR):
    """
    A StandardP2TR where all the transitions are given by a StandardClause.
    """

    def __init__(self, internal_pubkey: bytes, clauses: list[StandardClause]):
        super().__init__(internal_pubkey, list(map(lambda x: (x.name, x.script), clauses)))
        self.clauses = clauses
        self._clauses_dict = {clause.name: clause for clause in clauses}

    def get_scripts(self) -> list[tuple[str, CScript]]:
        return list(map(lambda clause: (clause.name, clause.script), self.clauses))

    def decode_wit_stack(self, stack_elems: list[bytes]) -> tuple[str, dict]:
        leaf_hash = stack_elems[-2]

        clause_name = None
        for clause in self.clauses:
            if leaf_hash == self.get_tr_info().leaves[clause.name].script:
                clause_name = clause.name
                break
        if clause_name is None:
            raise ValueError("Clause not found")

        return clause_name, self._clauses_dict[clause_name].args_from_stack_elements(stack_elems[:-2])

    def __repr__(self):
        return f"{self.__class__.__name__}(internal_pubkey={self.internal_pubkey.hex()})"


class StandardAugmentedP2TR(AugmentedP2TR):
    """
    An AugmentedP2TR where all the transitions are given by a StandardClause.
    """

    def __init__(self, naked_internal_pubkey: bytes, clauses: list[StandardClause]):
        super().__init__(naked_internal_pubkey)
        self.clauses = clauses
        self._clauses_dict = {clause.name: clause for clause in clauses}

    def get_scripts(self) -> list[tuple[str, CScript]]:
        return list(map(lambda clause: (clause.name, clause.script), self.clauses))

    def decode_wit_stack(self, data: bytes, stack_elems: list[bytes]) -> tuple[str, dict]:
        leaf_hash = stack_elems[-2]

        clause_name = None
        for clause in self.clauses:
            if leaf_hash == self.get_tr_info(data).leaves[clause.name].script:
                clause_name = clause.name
                break
        if clause_name is None:
            raise ValueError("Clause not found")

        return clause_name, self._clauses_dict[clause_name].args_from_stack_elements(stack_elems[:-2])

    def __repr__(self):
        return f"{self.__class__.__name__}(naked_internal_pubkey={self.naked_internal_pubkey.hex()})"


class ContractInstanceStatus(Enum):
    ABSTRACT = 0
    FUNDED = 1
    SPENT = 2


class ContractInstance:
    def __init__(self, contract: StandardP2TR | StandardAugmentedP2TR):
        self.contract = contract
        self.data = None if not self.is_augm() else b'\0'*32

        self.data_expanded = None # TODO: figure out a good API for this

        self.last_height = 0

        self.status = ContractInstanceStatus.ABSTRACT
        self.outpoint: COutPoint | None = None
        self.funding_tx: CTransaction | None = None

        self.spending_tx: CTransaction | None = None
        self.spending_vin = None

        self.spending_clause = None
        self.spending_args = None

        # Once spent, the list of ContractInstances produced
        self.next = None

    def is_augm(self) -> bool:
        return isinstance(self.contract, AugmentedP2TR) or isinstance(self.contract, StandardAugmentedP2TR)

    def get_tr_info(self) -> TaprootInfo:
        if not self.is_augm():
            return self.contract.get_tr_info()
        else:
            assert self.data is not None
            return self.contract.get_tr_info(self.data)

    def get_address(self) -> str:
        return encode_segwit_address("bcrt", 1, bytes(self.get_tr_info().scriptPubKey)[2:])

    def get_value(self) -> int:
        if self.funding_tx is None:
            raise ValueError("contract not funded, or funding transaction unknown")
        return self.funding_tx.vout[self.outpoint.n].nValue

    def decode_wit_stack(self, stack_elems: list[bytes]) -> tuple[str, dict]:
        if self.is_augm():
            return self.contract.decode_wit_stack(self.data, stack_elems)
        else:
            return self.contract.decode_wit_stack(stack_elems)

    def __repr__(self):
        value = None
        if self.status != ContractInstanceStatus.ABSTRACT:
            value = self.funding_tx.vout[self.outpoint.n].nValue
        return f"{self.__class__.__name__}(contract={self.contract}, data={self.data if self.data is None else self.data.hex()}, value={value}, status={self.status}, outpoint={self.outpoint})"


class ContractManager:
    def __init__(self, contract_instances: list[ContractInstance], rpc: AuthServiceProxy, *, mine_automatically=False):
        self.instances = contract_instances
        self.mine_automatically = mine_automatically
        self.rpc = rpc

    def _check_instance(self, instance: ContractInstance, exp_statuses: None | ContractInstanceStatus | list[ContractInstanceStatus] = None):
        if exp_statuses is not None:
            if isinstance(exp_statuses, ContractInstanceStatus):
                if instance.status != exp_statuses:
                    raise ValueError(f"Instance in status {instance.status}, but expected {exp_statuses}")
            else:
                if instance.status not in exp_statuses:
                    raise ValueError(f"Instance in unexpected status {instance.status}")

        if instance not in self.instances:
            raise ValueError("Instance not in this manager")

    def add_instance(self, instance: ContractInstance):
        self.instances.append(instance)

    def wait_for_outpoint(self, instance: ContractInstance, txid: str | None = None):
        self._check_instance(instance, exp_statuses=ContractInstanceStatus.ABSTRACT)
        if instance.is_augm():
            if instance.data is None:
                raise ValueError("Data not set in instance")
            scriptPubKey = instance.contract.get_tr_info(instance.data).scriptPubKey
        else:
            scriptPubKey = instance.contract.get_tr_info().scriptPubKey

        if self.mine_automatically:
            self._mine_blocks(1)

        instance.outpoint, instance.last_height = wait_for_output(self.rpc, scriptPubKey, txid=txid)

        funding_tx_raw = self.rpc.getrawtransaction(instance.outpoint.hash.to_bytes(32, byteorder="big").hex())
        funding_tx = CTransaction()
        funding_tx.deserialize(BytesIO(bytes.fromhex(funding_tx_raw)))
        instance.funding_tx = funding_tx

        instance.status = ContractInstanceStatus.FUNDED

    def get_spend_tx(
            self,
            spends: tuple[ContractInstance, str, dict] | list[tuple[ContractInstance, str, dict]],
            output_amounts: dict[int, int] = {}
        ) -> tuple[CTransaction, list[bytes]]:
        if not isinstance(spends, list):
            spends = [spends]

        tx = CTransaction()
        tx.nVersion = 2
        outputs_map: dict[int, CTxOut] = {}

        tx.vin = [CTxIn(outpoint=instance.outpoint) for instance, _, _ in spends]

        has_ctv_clause = False

        for input_index, (instance, clause_name, args) in enumerate(spends):
            clause_idx = next((i for i, clause in enumerate(instance.contract.clauses)
                              if clause.name == clause_name), None)
            if clause_idx is None:
                raise ValueError(f"Clause {clause_name} not found")
            clause = instance.contract.clauses[clause_idx]

            next_outputs = clause.next_outputs(args)
            if isinstance(next_outputs, CTransaction):
                if len(tx.vin) != 1 or len(next_outputs.vin) != 1:
                    raise ValueError("CTV clauses are only supported for single-input spends")  # TODO: generalize

                tx.vin[0].nSequence = next_outputs.vin[0].nSequence
                tx.vout = next_outputs.vout
                has_ctv_clause = True
            else:
                preserve_output_used = False
                ccv_amount = instance.funding_tx.vout[instance.outpoint.n].nValue
                for clause_output in next_outputs:
                    out_contract = clause_output.next_contract
                    if isinstance(out_contract, (P2TR, OpaqueP2TR)):
                        out_scriptPubKey = out_contract.get_tr_info().scriptPubKey
                    elif isinstance(out_contract, AugmentedP2TR):
                        if clause_output.next_data is None:
                            raise ValueError("Missing data for augmented output")
                        out_scriptPubKey = out_contract.get_tr_info(clause_output.next_data).scriptPubKey
                    else:
                        raise ValueError("Unsupported contract type")

                    if clause_output.n in outputs_map:
                        if outputs_map[clause_output.n].scriptPubKey != out_scriptPubKey:
                            raise ValueError(
                                f"Clashing output script for output {clause_output.n}: specifications for input {input_index} don't match a previous one")
                    else:
                        outputs_map[clause_output.n] = CTxOut(0, out_scriptPubKey)

                    if clause_output.next_amount == ClauseOutputAmountBehaviour.PRESERVE_OUTPUT:
                        outputs_map[clause_output.n].nValue += ccv_amount
                        preserve_output_used = True
                    elif clause_output.next_amount == ClauseOutputAmountBehaviour.DEDUCT_OUTPUT:
                        if preserve_output_used:
                            raise ValueError("DEDUCT_OUTPUT clause outputs must be declared before PRESERVE_OUTPUT clause outputs")
                        if clause_output.n not in output_amounts:
                            raise ValueError("The output amount must be specified for clause outputs using DEDUCT_AMOUNT")

                        outputs_map[clause_output.n].nValue = output_amounts[clause_output.n]
                        ccv_amount -= output_amounts[clause_output.n]
                    else:
                        raise ValueError("Only PRESERVE_OUTPUT and DEDUCT_OUTPUT clause outputs are supported")

        if not has_ctv_clause:
            if set(outputs_map.keys()) != set(range(len(outputs_map))):
                raise ValueError("Some outputs are not correctly specified")
            tx.vout = [outputs_map[i] for i in range(len(outputs_map))]

        # TODO: generalize for keypath spend?
        sighashes: list[bytes] = []
        spent_utxos = []

        # TODO: simplify
        for input_index in range(len(tx.vin)):
            instance = spends[input_index][0]
            spent_utxos.append(instance.funding_tx.vout[instance.outpoint.n]),

        for input_index in range(len(tx.vin)):
            instance = spends[input_index][0]
            clause_name = spends[input_index][1]

            sighashes.append(script.TaprootSignatureHash(
                tx,
                spent_utxos,
                input_index=input_index,
                hash_type=0,
                scriptpath=True,
                script=instance.get_tr_info().leaves[clause_name].script
            ))
        return tx, sighashes

    # args is the same, but it includes witness args (e.g. signatures)
    def get_spend_wit(self, instance: ContractInstance, clause_name: str, wargs: dict) -> CTxInWitness:
        clause_idx = next((i for i, clause in enumerate(instance.contract.clauses) if clause.name == clause_name), None)
        if clause_idx is None:
            raise ValueError(f"Clause {clause_name} not found")
        clause = instance.contract.clauses[clause_idx]

        in_wit = CTxInWitness()
        in_wit.scriptWitness.stack = [
            *clause.stack_elements_from_args(wargs),
            instance.get_tr_info().leaves[clause_name].script,
            instance.get_tr_info().controlblock_for_script_spend(clause_name),
        ]
        return in_wit

    def _mine_blocks(self, n_blocks: int = 1) -> list[str]:
        address = self.rpc.getnewaddress()
        return self.rpc.generatetoaddress(n_blocks, address)

    def spend_and_wait(self, instances: ContractInstance | list[ContractInstance], tx: CTransaction) -> list[ContractInstance]:
        if isinstance(instances, ContractInstance):
            instances = [instances]

        cur_height = self.rpc.getblockcount()
        for instance in instances:
            self._check_instance(instance, exp_statuses=ContractInstanceStatus.FUNDED)
            instance.last_height = cur_height

        self.rpc.sendrawtransaction(tx.serialize().hex())

        if self.mine_automatically:
            self._mine_blocks(1)
        return self.wait_for_spend(instances)

    def wait_for_spend(self, instances: ContractInstance | list[ContractInstance]) -> list[ContractInstance]:
        if isinstance(instances, ContractInstance):
            instances = [instances]

        out_contracts: dict[int, ContractInstance] = {}

        for instance in instances:
            self._check_instance(instance, exp_statuses=ContractInstanceStatus.FUNDED)

            tx, vin, instance.last_height = wait_for_spending_tx(
                self.rpc,
                instance.outpoint,
                starting_height=instance.last_height
            )
            tx.rehash()

            instance.spending_tx = tx
            instance.spending_vin = vin
            instance.status = ContractInstanceStatus.SPENT

            # decode spend
            in_wit: CTxInWitness = tx.wit.vtxinwit[vin]

            instance.spending_clause, instance.spending_args = instance.decode_wit_stack(in_wit.scriptWitness.stack)

            clause_idx = next((i for i, clause in enumerate(instance.contract.clauses)
                              if clause.name == instance.spending_clause), None)
            if clause_idx is None:
                raise ValueError(f"Clause {instance.spending_clause} not found")
            clause = instance.contract.clauses[clause_idx]

            next_outputs = clause.next_outputs(instance.spending_args)

            # We go through all the outputs produced by spending this transaction,
            # and add them to the manager if they are standard
            if isinstance(next_outputs, CTransaction):
                # For now, we assume CTV clauses are terminal;
                # this might be generalized in the future
                pass
            else:
                for clause_output in next_outputs:
                    if clause_output.n in out_contracts:
                        continue  # output already specified by another input

                    out_contract = clause_output.next_contract
                    new_instance = ContractInstance(out_contract)

                    if isinstance(out_contract, (P2TR, OpaqueP2TR, StandardP2TR)):
                        continue  # nothing to do, will not track this output
                    elif isinstance(out_contract, StandardAugmentedP2TR):
                        if clause_output.next_data is None:
                            raise ValueError("Missing data for augmented output")
                        new_instance.data = clause_output.next_data
                    else:
                        raise ValueError("Unsupported contract type")

                    new_instance.last_height = instance.last_height

                    new_instance.outpoint = COutPoint(int(tx.hash, 16), clause_output.n)
                    new_instance.funding_tx = tx
                    new_instance.status = ContractInstanceStatus.FUNDED

                    out_contracts[clause_output.n] = new_instance

        result = list(out_contracts.values())
        for instance in result:
            self.add_instance(instance)
        return result
