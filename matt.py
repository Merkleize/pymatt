from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from typing import Callable
from btctools import script, key
from btctools.auth_proxy import AuthServiceProxy
from btctools.messages import COutPoint, CTransaction, CTxIn, CTxInWitness
from btctools.script import OP_1, CScript, CTxOut, TaprootInfo
from btctools.segwit_addr import encode_segwit_address
from utils import wait_for_output, wait_for_spending_tx

# Flags for OP_CHECKCONTRACTVERIFY
CCV_FLAG_CHECK_INPUT: int = 1
CCV_FLAG_IGNORE_OUTPUT_AMOUNT: int = 2

# point with provably unknown private key
NUMS_KEY: bytes = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


def vch2bn(s: bytes) -> int:
    """Convert bitcoin-specific little endian format to number."""
    if len(s) == 0:
        return 0
    # The most significant bit is the sign bit.
    is_negative = s[0] & 0x80 != 0
    # Mask off the sign bit.
    s_abs = bytes([s[0] & 0x7f]) + s[1:]
    v_abs = int.from_bytes(s_abs, 'little')
    # Return as negative number if it's negative.
    return -v_abs if is_negative else v_abs


class AbstractContract:
    pass


class ClauseOutputAmountBehavior(Enum):
    PRESERVE_OUTPUT = 0  # The output should be at least as large as the input
    IGNORE_OUTPUT = 1  # The output amount is not checked


@dataclass
class ClauseOutput:
    n: None | int
    next_contract: AbstractContract  # only StandardP2TR and StandardAugmentedP2TR are supported so far
    next_data: None | bytes = None  # only meaningful if c is augmented
    next_amount: ClauseOutputAmountBehavior = ClauseOutputAmountBehavior.PRESERVE_OUTPUT

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


StandardType = type[int] | type[bytes]


ArgSpecs = list[tuple[str, StandardType]]


# A StandardClause encodes simple scripts where the witness is exactly
# a list of arguments, always in the same order, and each is either
# an integer or a byte array.
# Other types of generic treatable clauses could be defined (for example, a MiniscriptClause).
# Moreover, it specifies a function that converts the arguments of the clause, to the data of the next output.
class StandardClause(Clause):
    def __init__(self, name: str, script: CScript, arg_specs: ArgSpecs, next_output_fn: Callable[[dict], list[ClauseOutput] | CTransaction] | None = None):
        super().__init__(name, script)
        self.arg_specs = arg_specs

        self.next_outputs_fn = next_output_fn

        for _, arg_cls in self.arg_specs:
            if arg_cls not in [int, bytes]:
                raise ValueError(f"Unsupported type: {arg_cls.__name__}")

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
            if type(arg_value) != arg_cls:
                raise ValueError(
                    f"Argument {arg_name} must be of type {arg_cls.__name__}, not {type(arg_value).__name__}")
            if arg_cls == int:
                result.append(script.bn2vch(arg_value))
            elif arg_cls == bytes:
                result.append(arg_value)
            else:
                raise ValueError("Unexpected type")  # this should never happen

        return result

    def args_from_stack_elements(self, elements: list[bytes]) -> dict:
        result: dict = {}
        if len(elements) != len(self.arg_specs):
            raise ValueError(f"Expected {len(self.arg_specs)} elements, not {len(elements)}")
        for i, (arg_name, arg_cls) in enumerate(self.arg_specs):
            if arg_cls == int:
                result[arg_name] = vch2bn(elements[i])
            elif arg_cls == bytes:
                result[arg_name] = elements[i]
            else:
                raise ValueError("Unexpected type")  # this should never happen
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
        return f"{self.__class__.__name__}(naked_internal_pubkey={self.naked_internal_pubkey.hex()})"


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

        self.last_height = 0

        self.status = ContractInstanceStatus.ABSTRACT
        self.outpoint = None
        self.funding_tx = None

        self.spending_tx = None
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
            scriptPubKey = instance.contract.get_tr_info(self.data).scriptPubKey
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
            spends: tuple[ContractInstance, str, dict] | list[tuple[ContractInstance, str, dict]]) -> tuple[CTransaction, list[bytes]]:
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
                for i, clause_output in enumerate(next_outputs):
                    out_contract = clause_output.next_contract
                    if isinstance(out_contract, (P2TR, OpaqueP2TR)):
                        out_scriptPubKey = out_contract.get_tr_info().scriptPubKey
                    elif isinstance(out_contract, AugmentedP2TR):
                        if clause_output.next_data is None:
                            raise ValueError("Missing data for augmented output")
                        out_scriptPubKey = out_contract.get_tr_info(clause_output.next_data).scriptPubKey
                    else:
                        raise ValueError("Unsupported contract type")

                    if i in outputs_map:
                        if outputs_map[i].scriptPubKey != out_scriptPubKey:
                            raise ValueError(
                                f"Clashing output script for output {i}: specifications for input {input_index} don't match a previous one")
                    else:
                        outputs_map[i] = CTxOut(0, out_scriptPubKey)

                    if clause_output.next_amount != ClauseOutputAmountBehavior.PRESERVE_OUTPUT:
                        raise ValueError("Output template not preserving the output amount is not supported")
                    else:
                        outputs_map[i].nValue += instance.funding_tx.vout[instance.outpoint.n].nValue

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

    def _mine_blocks(self, n_blocks: int = 1):
        address = self.rpc.getnewaddress()
        self.rpc.generatetoaddress(n_blocks, address)

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
                for i, clause_output in enumerate(next_outputs):
                    assert clause_output.n == i  # for now, we only accept templates where all the outputs are described

                    if i in out_contracts:
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

                    new_instance.outpoint = COutPoint(int(tx.hash, 16), i)
                    new_instance.funding_tx = tx
                    new_instance.status = ContractInstanceStatus.FUNDED

                    out_contracts[i] = new_instance

        result = list(out_contracts.values())
        for instance in result:
            self.add_instance(instance)
        return result
