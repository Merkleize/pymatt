# Encapsulates a blind signer for one or more known keys.
# Used by the ContractManager to sign for the clause arguments of SignerType type.
#
# In the real world, we wouldn't blindly sign a hash, so the `sign` method
# would include other info to help the signer decide (e.g.: the transaction)
# There are no bad people here, though, so we keep it simple for now.
from enum import Enum
from io import BytesIO
from typing import Dict, List, Optional, Tuple, Union

from .argtypes import SignerType
from .btctools import script
from .btctools.auth_proxy import AuthServiceProxy
from .btctools.key import ExtendedKey, sign_schnorr
from .btctools.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from .btctools.script import TaprootInfo
from .btctools.segwit_addr import encode_segwit_address
from .contracts import P2TR, AugmentedP2TR, ClauseOutputAmountBehaviour, OpaqueP2TR, StandardAugmentedP2TR, StandardP2TR
from .utils import wait_for_output, wait_for_spending_tx


class SchnorrSigner:
    def __init__(self, keys: Union[ExtendedKey, List[ExtendedKey]]):
        if not isinstance(keys, list):
            keys = [keys]

        for key in keys:
            if not key.is_private:
                raise ValueError("The SchnorrSigner needs the private keys")

        self.keys = keys

    def sign(self, msg: bytes, pubkey: bytes) -> Optional[bytes]:
        if len(msg) != 32:
            raise ValueError("msg should be 32 bytes long")
        if len(pubkey) != 32:
            raise ValueError("pubkey should be an x-only pubkey")

        for k in self.keys:
            if k.pubkey[1:] == pubkey:
                return sign_schnorr(k.privkey, msg)

        return None


class ContractInstanceStatus(Enum):
    ABSTRACT = 0
    FUNDED = 1
    SPENT = 2


class ContractInstance:
    def __init__(self, contract: Union[StandardP2TR, StandardAugmentedP2TR]):
        self.contract = contract
        self.data = None if not self.is_augm() else b'\0'*32

        self.data_expanded = None  # TODO: figure out a good API for this

        self.manager: ContractManager = None

        self.last_height = 0

        self.status = ContractInstanceStatus.ABSTRACT
        self.outpoint: Optional[COutPoint] = None
        self.funding_tx: Optional[CTransaction] = None

        self.spending_tx: Optional[CTransaction] = None
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

    def decode_wit_stack(self, stack_elems: List[bytes]) -> Tuple[str, dict]:
        if self.is_augm():
            return self.contract.decode_wit_stack(self.data, stack_elems)
        else:
            return self.contract.decode_wit_stack(stack_elems)

    def __repr__(self):
        value = None
        if self.status != ContractInstanceStatus.ABSTRACT:
            value = self.funding_tx.vout[self.outpoint.n].nValue
        return f"{self.__class__.__name__}(contract={self.contract}, data={self.data if self.data is None else self.data.hex()}, value={value}, status={self.status}, outpoint={self.outpoint})"

    def __call__(self, clause_name: str, *, signer: Optional[SchnorrSigner] = None, outputs: List[CTxOut] = [], **kwargs) -> List['ContractInstance']:
        if self.manager is None:
            raise ValueError("Direct invocation is only allowed after adding the instance to a ContractManager")

        if self.status != ContractInstanceStatus.FUNDED:
            raise ValueError("Only implemented for FUNDED instances")

        return self.manager.spend_instance(self, clause_name, kwargs, signer=signer, outputs=outputs)


class ContractManager:
    def __init__(self, contract_instances: List[ContractInstance], rpc: AuthServiceProxy, *, poll_interval: float = 1, mine_automatically: bool = False):
        self.instances = contract_instances
        self.mine_automatically = mine_automatically
        self.rpc = rpc
        self.poll_interval = poll_interval

    def _check_instance(self, instance: ContractInstance, exp_statuses: Optional[Union[ContractInstanceStatus, List[ContractInstanceStatus]]] = None):
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
        if instance.manager is not None:
            raise ValueError("The instance can only be added to one ContractManager")

        instance.manager = self
        self.instances.append(instance)

    def wait_for_outpoint(self, instance: ContractInstance, txid: Optional[str] = None):
        self._check_instance(instance, exp_statuses=ContractInstanceStatus.ABSTRACT)
        if instance.is_augm():
            if instance.data is None:
                raise ValueError("Data not set in instance")
            scriptPubKey = instance.contract.get_tr_info(instance.data).scriptPubKey
        else:
            scriptPubKey = instance.contract.get_tr_info().scriptPubKey

        if self.mine_automatically:
            self._mine_blocks(1)

        instance.outpoint, instance.last_height = wait_for_output(
            self.rpc, scriptPubKey, txid=txid, poll_interval=self.poll_interval)

        funding_tx_raw = self.rpc.getrawtransaction(instance.outpoint.hash.to_bytes(32, byteorder="big").hex())
        funding_tx = CTransaction()
        funding_tx.deserialize(BytesIO(bytes.fromhex(funding_tx_raw)))
        instance.funding_tx = funding_tx

        instance.status = ContractInstanceStatus.FUNDED

    def get_spend_tx(
        self,
        spends: Union[Tuple[ContractInstance, str, dict], List[Tuple[ContractInstance, str, dict]]],
        output_amounts: Dict[int, int] = {}
    ) -> Tuple[CTransaction, List[bytes]]:
        if not isinstance(spends, list):
            spends = [spends]

        tx = CTransaction()
        tx.nVersion = 2
        outputs_map: Dict[int, CTxOut] = {}

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
                            raise ValueError(
                                "DEDUCT_OUTPUT clause outputs must be declared before PRESERVE_OUTPUT clause outputs")
                        if clause_output.n not in output_amounts:
                            raise ValueError(
                                "The output amount must be specified for clause outputs using DEDUCT_AMOUNT")

                        outputs_map[clause_output.n].nValue = output_amounts[clause_output.n]
                        ccv_amount -= output_amounts[clause_output.n]
                    else:
                        raise ValueError("Only PRESERVE_OUTPUT and DEDUCT_OUTPUT clause outputs are supported")

        if not has_ctv_clause:
            if set(outputs_map.keys()) != set(range(len(outputs_map))):
                raise ValueError("Some outputs are not correctly specified")
            tx.vout = [outputs_map[i] for i in range(len(outputs_map))]

        # TODO: generalize for keypath spend?
        sighashes: List[bytes] = []
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

    def _mine_blocks(self, n_blocks: int = 1) -> List[str]:
        address = self.rpc.getnewaddress()
        return self.rpc.generatetoaddress(n_blocks, address)

    def spend_and_wait(self, instances: Union[ContractInstance, List[ContractInstance]], tx: CTransaction) -> List[ContractInstance]:
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

    def wait_for_spend(self, instances: Union[ContractInstance, List[ContractInstance]]) -> List[ContractInstance]:
        if isinstance(instances, ContractInstance):
            instances = [instances]

        out_contracts: Dict[int, ContractInstance] = {}

        for instance in instances:
            self._check_instance(instance, exp_statuses=ContractInstanceStatus.FUNDED)

            tx, vin, instance.last_height = wait_for_spending_tx(
                self.rpc,
                instance.outpoint,
                starting_height=instance.last_height,
                poll_interval=self.poll_interval
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

    def fund_instance(self, contract: Union[StandardP2TR, StandardAugmentedP2TR], amount: int, data: Optional[bytes] = None) -> ContractInstance:
        """
        Convenience method to create an instance of a contract, add it to the ContractManager,
        and send a transaction to fund it with a certain amount.
        """
        instance = ContractInstance(contract)

        if isinstance(contract, StandardP2TR) and data is not None:
            raise ValueError("The data must be None for a contract with no embedded data")

        if isinstance(contract, StandardAugmentedP2TR):
            if data is None:
                raise ValueError("The data must be provided for an augmented P2TR contract instance")
            instance.data = data
        self.add_instance(instance)
        txid = self.rpc.sendtoaddress(instance.get_address(), amount/100_000_000)
        self.wait_for_outpoint(instance, txid)
        return instance

    def spend_instance(self, instance: ContractInstance, clause_name: str, args: dict, *, signer: Optional[SchnorrSigner], outputs: Optional[List[CTxOut]] = None) -> List[ContractInstance]:
        """
        Creates and broadcasts a transaction that spends a contract instance using a specified clause and arguments.

        :param instance: The ContractInstance to spend from.
        :param clause_name: The name of the clause to be executed in the contract.
        :param args: A dictionary of arguments required for the clause.
        :param outputs: if not None, a list of CTxOut to add at the end of the list of
                        outputs generated by the clause.
        :return: A list of ContractInstances resulting from the spend transaction.
        """
        spend_tx, sighashes = self.get_spend_tx((instance, clause_name, args))

        assert len(sighashes) == 1

        sighash = sighashes[0]

        if outputs is not None:
            spend_tx.vout.extend(outputs)

        clause = instance.contract._clauses_dict[clause_name]  # TODO: refactor, accessing private member
        for arg_name, arg_type in clause.arg_specs:
            if isinstance(arg_type, SignerType):
                if signer is None:
                    raise ValueError("No signer was provided, but the witness requires signatures")
                args[arg_name] = signer.sign(sighash, arg_type.pubkey)

        spend_tx.wit.vtxinwit = [self.get_spend_wit(instance, clause_name, args)]
        result = self.spend_and_wait(instance, spend_tx)

        return result
