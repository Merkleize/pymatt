"""
This Python module provides a framework for funding, spending and tracking contract instances.

The ContractInstance class represents encodes the lifetime of a standard Contract instance;
if augmented, it also keeps track of its internal state.

The ContractManager keeps track of a list of ContractInstance, and has methods for
- funding a Contract, by sending funds to a Contract address;
- spending a ContractInstance, possibly creating new ContractInstances as a result;
- waiting for a ContractInstance to be spent, possibly creating new ContractInstances as a result of decoding
  the transaction.

At this time, this only works on regtest.
"""

from enum import Enum
from io import BytesIO
from typing import Callable, Dict, Generic, List, Optional, Tuple, TypeVar, Union

from typing_extensions import TypeGuard

from .argtypes import SignerType
from .btctools import script
from .btctools.auth_proxy import AuthServiceProxy
from .btctools.key import ExtendedKey, sign_schnorr
from .btctools.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from .btctools.script import TaprootInfo
from .btctools.segwit_addr import encode_segwit_address
from .contracts import P2TR, AugmentedP2TR, ClauseOutputAmountBehaviour, OpaqueP2TR, StandardAugmentedP2TR, StandardP2TR, ContractState
from .utils import wait_for_output, wait_for_spending_tx


class SchnorrSigner:
    """
    Encapsulates a blind signer for one or more known keys. It's utilized within the ContractManager to 
    sign arguments of clauses whose type is SignerType.

    In the real world, we wouldn't blindly sign a hash, so the `sign` method would include other info to
    help the signer decide (e.g.: the transaction).
    For the purposes of demos, this is good enough.
    """

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
    """Represents each of the possible conditions of a ContractInstance lifetime"""
    ABSTRACT = 0  # Before being funded, no attached UTXO, nor any defined state.
    FUNDED = 1    # Funded, attached to a specific UTXO; if augmented, its state is defined.
    SPENT = 2     # Already spent


ContractT = TypeVar('ContractT', bound=Union[StandardP2TR, StandardAugmentedP2TR])


class ContractInstance(Generic[ContractT]):
    """
    Represents a specific instance of a Contract. It keeps track of:
    - the instance status
    - if augmented, the data embedded in the Contract instance.
    """

    def __init__(self, contract: ContractT):
        """
        Initializes a new ContractInstance with the given contract template.

        Parameters:
            contract (Union[StandardP2TR, StandardAugmentedP2TR]): The contract template for this instance,
                which can either be a standard or augmented Pay-to-Taproot contract.
        """

        self.contract = contract
        self.data: Optional[bytes] = None
        self.data_expanded: Optional[ContractState] = None  # TODO: figure out a good API for this

        self.manager: Optional[ContractManager] = None

        self.last_height = 0

        self.status = ContractInstanceStatus.ABSTRACT
        self.outpoint: Optional[COutPoint] = None
        self.funding_tx: Optional[CTransaction] = None

        # The following fields are filled when the instance is spent
        self.spending_tx: Optional[CTransaction] = None
        self.spending_vin: Optional[int] = None
        self.spending_clause: Optional[str] = None
        self.spending_args: Optional[dict] = None
        # the new instances produced by spending this instance
        self.next: Optional[List[ContractInstance]] = None

    def is_augmented(self) -> TypeGuard['ContractInstance[StandardAugmentedP2TR]']:
        """
        Checks if the Contract contained in this instance is augmented.

        Returns:
            bool: True if the contract is augmented, False otherwise.
        """
        return isinstance(self.contract, StandardAugmentedP2TR)

    def get_tr_info(self) -> TaprootInfo:
        """
        Returns the associated TaprootInfo object.

        Returns:
            TaprootInfo: An object with info about the taptree.

        Raises:
            ValueError: If the contract is augmented but no data is set for the instance.
        """
        if not self.is_augmented():
            return self.contract.get_tr_info()
        else:
            if self.data is None:
                raise ValueError("Cannot generate address for augmented instance before setting the data")
            return self.contract.get_tr_info(self.data)

    def get_address(self) -> str:
        """
        Computes the associated regtest address for this contract instance.

        Returns:
            str: The Bitcoin address for this contract instance.

        Raises:
            ValueError: If the contract is augmented but no data is set for the instance.
        """

        return encode_segwit_address("bcrt", 1, bytes(self.get_tr_info().scriptPubKey)[2:])

    def get_value(self) -> int:
        """
        Returns the value (amount) of this contract instance.

        Returns:
            int: The value in satoshis locked in the contract's funding transaction.

        Raises:
            ValueError: If the contract instance is not funded, meaning the funding transaction is unknown.
        """

        if self.funding_tx is None:
            raise ValueError("contract not funded, or funding transaction unknown")
        return self.funding_tx.vout[self.outpoint.n].nValue

    def decode_wit_stack(self, stack_elems: List[bytes]) -> Tuple[str, dict]:
        """
        Decodes the witness stack from a spending transaction to extract the clause name and arguments used in the spend.

        Parameters:
            stack_elems (List[bytes]): The witness stack elements from the spending transaction.

        Returns:
            Tuple[str, dict]: A tuple containing the name of the clause used and a dictionary of the arguments provided to the clause.
        """
        if self.is_augmented():
            assert self.data is not None

            return self.contract.decode_wit_stack(self.data, stack_elems)
        else:
            return self.contract.decode_wit_stack(stack_elems)

    def __repr__(self):
        value = None
        if self.status != ContractInstanceStatus.ABSTRACT:
            value = self.funding_tx.vout[self.outpoint.n].nValue
        return f"{self.__class__.__name__}(contract={self.contract}, data={self.data if self.data is None else self.data.hex()}, value={value}, status={self.status}, outpoint={self.outpoint})"

    def __call__(self, clause_name: str, signer: Optional[SchnorrSigner] = None, outputs: List[CTxOut] = []) -> Callable[..., List['ContractInstance']]:
        """
        Prepares a callable function that, when executed, will attempt to spend this contract instance using the specified clause and arguments.
        This method enables the contract instance to be used in a functional manner, allowing a natural interface to spend the instance
        with one of the clauses defined by the contract.

        Parameters:
            clause_name (str): The name of the clause to be executed in the contract spend, which must exist in the associated contract.
            signer (Optional[SchnorrSigner]): An optional SchnorrSigner instance that can provide the necessary signatures for the spend transaction.
            outputs (List[CTxOut]): An optional list of CTxOut objects representing outputs to be included in the spend transaction, in addition to
                any outputs that are defined by the contract.

        Returns:
            Callable[..., List['ContractInstance']]: A callable function that, when called with the appropriate arguments, will execute the spend transaction.
                The function will return a list of new ContractInstance objects created as a result of the spend, representing the next state(s) of the contract.

        Raises:
            ValueError: If the contract instance has not been added to a ContractManager.
            ValueError: If the contract instance's status is not FUNDED.
        """

        def callable_instance(**kwargs) -> List['ContractInstance']:
            if self.manager is None:
                raise ValueError("Direct invocation is only allowed after adding the instance to a ContractManager")

            if self.status != ContractInstanceStatus.FUNDED:
                raise ValueError("Only implemented for FUNDED instances")

            return self.manager.spend_instance(self, clause_name, kwargs, signer=signer, outputs=outputs)

        return callable_instance


class ContractManager:
    """
    Manages a collection of ContractInstance objects, coordinating their lifecycle within the Bitcoin blockchain. This includes
    operations like funding contracts, monitoring contract instance spends, and executing spend transactions according to contract logic.
    """

    def __init__(self, rpc: AuthServiceProxy, *, poll_interval: float = 1, mine_automatically: bool = False):
        """
        Initializes a new ContractManager object to manage a collection of Bitcoin contract instances.

        The manager is responsible for overseeing the lifecycle of contracts, including funding, spending, and tracking their state on the blockchain.
        It interfaces with a regtest Bitcoin node through the provided RPC client.

        Parameters:
            rpc (AuthServiceProxy): An RPC client configured to communicate with a regtest Bitcoin node.
            poll_interval (float, optional): The interval, in seconds, at which the manager will poll for updates on the managed contracts. Defaults to 1 second.
            mine_automatically (bool, optional): If set to True, the manager will attempt mine blocks to confirm pending transactions
                when waiting for a contract to be funded, or when using a contract clause.

        """

        self.instances: List[ContractInstance] = []

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
        """
        Adds a ContractInstance to the ContractManager's management scope.

        Parameters:
            instance (ContractInstance): The contract instance to be added to this manager's management scope.

        Raises:
            ValueError: If the contract instance is already managed by another ContractManager.
        """

        if instance.manager is not None:
            raise ValueError("The instance can only be added to one ContractManager")

        instance.manager = self
        self.instances.append(instance)

    def wait_for_outpoint(self, instance: ContractInstance, txid: Optional[str] = None):
        """
        Waits for a specific contract instance's funding transaction to be confirmed and updates the instance's
        status and details accordingly. This method is used when we expect a transaction that creates such an
        output to be created externally; therefore, it can only be used for a ContractInstance whose status is ABSTRACT.

        Parameters:
            instance (ContractInstance): The contract instance for which the funding transaction confirmation is awaited.
            txid (Optional[str]): The transaction ID of the funding transaction. If not provided, the method
                                  will search for any transactions matching the contract instance's scriptPubKey.

        Raises:
            ValueError: If the contract instance is not in the ABSTRACT state or if it is an augmented contract instance
                        without the necessary data set.

        Side Effects:
            - If `mine_automatically` is enabled, this method may trigger the mining of a block to ensure the funding
              transaction is confirmed.
            - Updates the provided contract instance's attributes such as `outpoint`, `last_height`, `funding_tx`, and `status`.
        """

        self._check_instance(instance, exp_statuses=ContractInstanceStatus.ABSTRACT)
        if instance.is_augmented():
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
        *,
        output_amounts: Dict[int, int] = {},
        outputs: List[CTxOut] = []
    ) -> Tuple[CTransaction, List[bytes]]:
        """
        Constructs a transaction intended to spend one or more contract instances based on specified clauses and arguments.

        This method allows for the creation of complex transactions that can spend multiple contracts in a single transaction,
        with the ability to specify custom outputs or rely on the contract's logic to determine the outputs.

        Parameters:
            spends (Union[Tuple[ContractInstance, str, dict], List[Tuple[ContractInstance, str, dict]]]): A single tuple or a list of tuples,
                where each tuple consists of a ContractInstance to be spent, the name of the clause to execute, and a dictionary of arguments
                required by that clause.
            output_amounts (Dict[int, int], optional): A dictionary mapping output indexes to satoshi amounts for outputs determined by the
                contract's clause logic but need to be explicitly specified. Used only for outputs defined by the clause with the
                DEDUCT_OUTPUT behavior. Defaults to an empty dictionary.
            outputs (List[CTxOut], optional): A list of CTxOut objects representing custom outputs to be included in the transaction,
                in addition to any outputs generated by the contract's logic. Defaults to an empty list.

        Returns:
            Tuple[CTransaction, List[bytes]]: A tuple containing the constructed CTransaction object and a list of byte arrays representing
                the sighash of each input, which will be used for signing the transaction.

        Raises:
            ValueError: If both `output_amounts` and `outputs` are provided, as they cannot be mixed within a single transaction.
                        Also raises an error if a specified clause is not found within a contract or if unsupported contract types are encountered.
        """

        if len(output_amounts) > 0 and len(outputs) > 0:
            # TODO: in principle, some outputs could be constrained by the clauses, and others could be completely specified
            # by the caller. For now, we don't support mixing
            raise ValueError("Either output_amounts or outputs must be given, but not both")

        if not isinstance(spends, list):
            spends = [spends]

        tx = CTransaction()
        tx.nVersion = 2

        if len(outputs) > 0:
            tx.vout = outputs

        outputs_map: Dict[int, CTxOut] = {}

        tx.vin = [CTxIn(outpoint=instance.outpoint) for instance, _, _ in spends]

        has_ctv_clause = False

        for input_index, (instance, clause_name, args) in enumerate(spends):
            clause_idx = next((i for i, clause in enumerate(instance.contract.clauses)
                              if clause.name == clause_name), None)
            if clause_idx is None:
                raise ValueError(f"Clause {clause_name} not found")
            clause = instance.contract.clauses[clause_idx]

            next_outputs = clause.next_outputs(args, instance.data_expanded)
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
                        if clause_output.next_state is None:
                            raise ValueError("Missing data for augmented output")
                        out_scriptPubKey = out_contract.get_tr_info(clause_output.next_state.encode()).scriptPubKey
                    else:
                        raise ValueError("Unsupported contract type")

                    out_index = input_index if clause_output.n == -1 else clause_output.n

                    if out_index in outputs_map:
                        if outputs_map[out_index].scriptPubKey != out_scriptPubKey:
                            raise ValueError(
                                f"Clashing output script for output {out_index}: specifications for input {input_index} don't match a previous one")
                    else:
                        outputs_map[out_index] = CTxOut(0, out_scriptPubKey)

                    if clause_output.next_amount == ClauseOutputAmountBehaviour.PRESERVE_OUTPUT:
                        outputs_map[out_index].nValue += ccv_amount
                        preserve_output_used = True
                    elif clause_output.next_amount == ClauseOutputAmountBehaviour.DEDUCT_OUTPUT:
                        if preserve_output_used:
                            raise ValueError(
                                "DEDUCT_OUTPUT clause outputs must be declared before PRESERVE_OUTPUT clause outputs")
                        if out_index not in output_amounts:
                            raise ValueError(
                                "The output amount must be specified for clause outputs using DEDUCT_AMOUNT")

                        outputs_map[out_index].nValue = output_amounts[out_index]
                        ccv_amount -= output_amounts[out_index]
                    else:
                        raise ValueError("Only PRESERVE_OUTPUT and DEDUCT_OUTPUT clause outputs are supported")

        if not has_ctv_clause and len(outputs_map) > 0:
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
    # TODO: might want to refactor this, it has a quite weird semantics. Only used in vaults.
    def get_spend_wit(self, instance: ContractInstance, clause_name: str, wargs: dict) -> CTxInWitness:
        """
        Constructs the witness stack required for spending a contract instance using a specified clause and arguments.

        Parameters:
            instance (ContractInstance): The contract instance being spent.
            clause_name (str): The name of the clause in the contract to be executed for this spend.
            wargs (dict): A dictionary of arguments required by the clause. These arguments are used to populate the witness
                          stack according to the clause's logic. This also includes the signature arguments.

        Returns:
            CTxInWitness: An object representing the witness stack for the spending transaction's input corresponding to
                          the contract instance being spent.
        """

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

    # TODO: rethink if the semantics for multiple instances is sound; only directly used in vaults
    def spend_and_wait(self, instances: Union[ContractInstance, List[ContractInstance]], tx: CTransaction) -> List[ContractInstance]:
        """
        Broadcasts a transaction that spends one or more contract instances and waits for the transaction to be confirmed,
        then updates the contract states and possibly creates new contract instances

        Parameters:
            instances (Union[ContractInstance, List[ContractInstance]]): The contract instance(s) that are being spent by the provided
                transaction. Can be a single ContractInstance or a list of ContractInstances.
            tx (CTransaction): The transaction object that spends the specified contract instance(s). This transaction should be properly
                constructed and signed before being passed to this method.

        Returns:
            List[ContractInstance]: A list of new ContractInstance objects that are created as a result of processing the spend transaction.
                These instances represent the new contracts that are formed from the outputs of the spent contracts, according to
                the clauses of the contract.

        Raises:
            ValueError: If any of the specified instances are not in the FUNDED state.

        Note:
            - If `mine_automatically` is set to True, this method will also trigger the mining of a new block.
            - The method blocks until the spend transaction is confirmed.
        """

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

    # TODO: rethink if the semantics for multiple instances is sound; only directly used in vaults
    def wait_for_spend(self, instances: Union[ContractInstance, List[ContractInstance]]) -> List[ContractInstance]:
        """
        Waits for one or more contract instances to be spent and processes the resulting transactions to update the contract
        states and possibly create new contract instances.

        This method polls the node until it finds a transaction that spends the specified contract instances. When such transaction
        is found, it updates the contract instances' states to SPENT, decodes the spending transactions to extract relevant data
        (such as the executed clause and its arguments), and creates new contract instances as dictated by the contract logic.

        Parameters:
            instances (Union[ContractInstance, List[ContractInstance]]): A single contract instance or a list of contract instances to monitor for spending transactions.

        Returns:
            List[ContractInstance]: A list of new contract instances created as a result of the spending transactions. This can include instances of contracts that are created as outputs of the spent contracts, according to the contract logic.

        Raises:
            ValueError: If any of the specified contract instances is not in the FUNDED state, or if the spending transaction references a clause that is not found in the contract.

        Note:
            This method is blocking and will continue to poll the blockchain until the specified contract instances are spent.
        """

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

            next_outputs = clause.next_outputs(instance.spending_args, instance.data_expanded)

            # We go through all the outputs produced by spending this transaction,
            # and add them to the manager if they are standard
            if isinstance(next_outputs, CTransaction):
                # For now, we assume CTV clauses are terminal;
                # this might be generalized in the future to support tracking
                # known output contracts in a CTV template
                pass
            else:
                next_instances: List[ContractInstance] = []
                for clause_output in next_outputs:
                    output_index = vin if clause_output.n == -1 else clause_output.n

                    if output_index in out_contracts:
                        next_instances.append(out_contracts[output_index])
                        continue  # output already specified by another input

                    out_contract = clause_output.next_contract
                    new_instance = ContractInstance(out_contract)

                    if isinstance(out_contract, (P2TR, OpaqueP2TR, StandardP2TR)):
                        continue  # nothing to do, will not track this output
                    elif isinstance(out_contract, StandardAugmentedP2TR):
                        if clause_output.next_state is None:
                            raise ValueError("Missing data for augmented output")
                        new_instance.data = clause_output.next_state.encode()
                        new_instance.data_expanded = clause_output.next_state
                    else:
                        raise ValueError("Unsupported contract type")

                    new_instance.last_height = instance.last_height

                    new_instance.outpoint = COutPoint(int(tx.hash, 16), output_index)
                    new_instance.funding_tx = tx
                    new_instance.status = ContractInstanceStatus.FUNDED

                    out_contracts[output_index] = new_instance

                    next_instances.append(new_instance)
                instance.next = next_instances

        result = list(out_contracts.values())
        for instance in result:
            self.add_instance(instance)
        return result

    def fund_instance(self, contract: ContractT, amount: int, data: Optional[ContractState] = None) -> ContractInstance[ContractT]:
        """
        Creates a new contract instance from a specified contract template, funds it with a specified amount of satoshis,
        and adds it to the manager.

        Parameters:
            contract (Union[StandardP2TR, StandardAugmentedP2TR]): The contract template to create an instance of. This can be
                either a standard P2TR contract or an augmented P2TR contract with additional data capabilities.
            amount (int): The amount in satoshis to fund the new contract instance with. This amount will be sent to the
                contract's address in a funding transaction.
            data (Optional[ContractState], optional): For augmented P2TR contracts, this parameter should provide the initial
                state data to be embedded within the contract instance. For standard P2TR contracts, this must be None.

        Returns:
            ContractInstance: The newly created and funded contract instance, which is now being managed by this ContractManager.

        Raises:
            ValueError: If an attempt is made to provide data for a (non-augmented) P2TR contract, or if data is not provided for
                an augmented P2TR contract.

        Note:
            - If `mine_automatically` is set to True, this method will also trigger the mining of a new block.
            - The method blocks until the spend transaction is confirmed.
        """

        instance = ContractInstance(contract)

        if isinstance(contract, StandardP2TR) and data is not None:
            raise ValueError("The data must be None for a contract with no embedded data")

        if isinstance(contract, StandardAugmentedP2TR):
            if data is None:
                raise ValueError("The data must be provided for an augmented P2TR contract instance")
            instance.data_expanded = data
            instance.data = data.encode()
        self.add_instance(instance)
        txid = self.rpc.sendtoaddress(instance.get_address(), amount/100_000_000)
        self.wait_for_outpoint(instance, txid)
        return instance

    def spend_instance(self, instance: ContractInstance, clause_name: str, args: dict, *, signer: Optional[SchnorrSigner], outputs: Optional[List[CTxOut]] = None) -> List[ContractInstance]:
        """
        Executes a spend transaction on a specified contract instance using a given clause and its associated arguments.
        This method constructs the transaction, signs it as necessary, and broadcasts it to the network.

        Parameters:
            instance (ContractInstance): The contract instance to be spent. This instance's status must be FUNDED.
            clause_name (str): The name of the clause within the contract to execute for this spend.
            args (dict): A dictionary containing the arguments required by the clause. Signatures are not included.
            signer (Optional[SchnorrSigner], optional): An optional SchnorrSigner object to sign the transaction if required by
                the clause. Defaults to None.
            outputs (Optional[List[CTxOut]], optional): An optional list of additional transaction outputs to include in the
                spend transaction. This allows for custom outputs beyond those defined by the contract's clause logic. Defaults to None.

        Returns:
            List[ContractInstance]: A list of new contract instances that result from the spend transaction.

        Raises:
            ValueError: If no signer is provided when required by the clause.

        Note:
            - If `mine_automatically` is set to True, this method will also trigger the mining of a new block.
            - The method blocks until the spend transaction is confirmed.
        """

        if outputs is None:
            outputs = []

        spend_tx, sighashes = self.get_spend_tx((instance, clause_name, args), outputs=outputs)

        assert len(sighashes) == 1

        sighash = sighashes[0]

        clause = instance.contract._clauses_dict[clause_name]  # TODO: refactor, accessing private member
        for arg_name, arg_type in clause.arg_specs:
            if isinstance(arg_type, SignerType):
                if signer is None:
                    raise ValueError("No signer was provided, but the witness requires signatures")
                args[arg_name] = signer.sign(sighash, arg_type.pubkey)

        spend_tx.wit.vtxinwit = [self.get_spend_wit(instance, clause_name, args)]
        result = self.spend_and_wait(instance, spend_tx)

        return result
