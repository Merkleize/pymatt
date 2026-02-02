import hashlib

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Optional, Tuple, Type, Union

from .argtypes import ArgType
from .btctools import script
from .btctools.key import tweak_add_pubkey
from .btctools.messages import CTransaction
from .btctools.script import OP_1, CScript, TaprootInfo
from .btctools.segwit_addr import encode_segwit_address


def tweak_embed_data(key: bytes, data: bytes) -> Optional[Tuple[bytes, Optional[bool]]]:
    """
    Tweaks a key with the sha256 hash of the data, returning the tweaked key and whether the result had to be negated.
    If the data is empty, the key is returned as is.
    """

    if len(data) == 0:
        return key, None

    data_tweak = hashlib.sha256(key + data).digest()
    return tweak_add_pubkey(key, data_tweak)


class AbstractContract:
    pass


class ContractState(ABC):
    """
    This class describes the "state" of a StandardAugmented contract, that is, the full data committed to
    inside the data tweak.
    """

    @abstractmethod
    def encode(self) -> bytes:
        """
        Computes the 32-byte data tweak that represents the commitment to the state of the contract.
        """
        pass

    @staticmethod
    @abstractmethod
    def encoder_script(*args, **kwargs) -> CScript:
        """
        Returns a CScript that computes the commitment to the state, assuming that the top of the stack contains the
        values of the individual stack items that allow to compute the state commitment, as output by the encode() function.
        Contracts might decide not to implement this (and raise an error if this is called), but they must document how the
        state commitment should be computed if not. Contracts implementing it should document what the expected stack
        elements are when the encoder_script is used.
        """
        pass


@dataclass
class EmptyState(ContractState):
    """
    Represents the empty state for stateless contracts.
    When used, the data tweak is empty (b''), which by tweak_embed_data semantics leaves the key unchanged.
    """

    def encode(self) -> bytes:
        return b''

    @staticmethod
    def encoder_script() -> CScript:
        return CScript([])


# Singleton instance for stateless contracts
EMPTY_STATE = EmptyState()


class ClauseOutputAmountBehaviour(Enum):
    """
    Defines the semantic of a clause with respect to an output's amount, where the output is enforced by OP_CHECKCONTRACTVERIFY.
    """

    PRESERVE_OUTPUT = 0  # The output should be at least as large as the input
    IGNORE_OUTPUT = 1  # The output amount is not checked
    DEDUCT_OUTPUT = 2  # The output amount is subtracted from the input


@dataclass
class ClauseOutput:
    """
    Represents a specific output defined by a contract clause, particularly in the context of contracts
    utilizing OP_CHECKCONTRACTVERIFY. The information is enough to construct the corresponding
    contract instance.

    This class encapsulates the details necessary to construct an output from a contract clause, including
    the output index, the contract of that output, the internal state of the output, and the amount semantic
    for that output.

    Attributes:
        n (Optional[int]): The index of the output. A value of -1 implies that the output's index equals
            the current input's index.
        next_contract (AbstractContract): The contract of this output.
        next_state (ContractState): The state data for the next contract instance. Defaults to EMPTY_STATE
            for stateless contracts.
        next_amount (ClauseOutputAmountBehaviour): Determines the semantic of the output amount.
    """

    n: int
    next_contract: AbstractContract
    next_state: 'ContractState' = EMPTY_STATE
    next_amount: ClauseOutputAmountBehaviour = ClauseOutputAmountBehaviour.PRESERVE_OUTPUT

    def __repr__(self):
        return f"ClauseOutput(n={self.n}, next_contract={self.next_contract}, next_state={self.next_state}, next_amount={self.next_amount})"


class Clause(ABC):
    """
    An abstract base class representing a clause, which encodes a spending condition of a contract.

    Each clause is associated with a unique name and a Script.

    Concrete implementations of this class implement methods to:
    - compute the correct witness stack, given a dictionary containing its arguments;
    - compute a list of clause outputs, based on the encumbrance of the clause Script;
    - decode the elements of the witness stack, obtaining the arguments that were used when executing the clause.
    """

    def __init__(self, name: str, script: CScript):
        self.name = name
        self.script = script

    @abstractmethod
    def stack_elements_from_args(self, args: dict) -> List[bytes]:
        """
        Given the arguments of the clause, computes the witness stack elements.

        Parameters:
            args (Dict): The arguments required by the clause.

        Returns:
            List[bytes]: The list of witness stack elements.
        """

        pass

    @abstractmethod
    def next_outputs(self, args: dict, state: ContractState = EMPTY_STATE) -> List[ClauseOutput]:
        """
        Determines the resulting outputs of the clause, based on the arguments of the clause,
        and the contract state.

        Parameters:
            args (Dict): The arguments of the claise.
            state (ContractState): The current state of the contract. Defaults to EMPTY_STATE for stateless contracts.

        Returns:
            List[ClauseOutput]: The outputs generated by the clause.
        """
        pass

    @abstractmethod
    def args_from_stack_elements(self, elements: List[bytes]) -> dict:
        """
        Reconstructs the the arguments that the clause was executed with, based on the
        witness stack of an input in a transaction.

        Parameters:
            elements (List[bytes]): The witness stack elements.

        Returns:
            Dict: The arguments of the clause, decoded from the witness stack elements.
        """
        pass

    def __repr__(self):
        return f"<Clause(name={self.name}, script={self.script})>"


class StandardClause(Clause):
    """
    Represents a well defined clause that is possibly encumbered by OP_CHECKCONTRACTVERIFY.
    A StandardClause defines the argument types as subclasses of ArgType, and defines a function to compute
    the next outputs based on the clause arguments, and the contract state.

    Note that it's up to the implementations to make sure that the specifications for the argument and the
    computation of the next outputs exactly match what is implied by the script.
    """

    def __init__(self, name: str, script: CScript, arg_specs: List[Tuple[str, ArgType]], next_outputs_fn: Optional[Callable[[dict, ContractState], Union[List[ClauseOutput], CTransaction]]] = None):
        """
        Initializes a StandardClause with the specified name, script, argument specifications, and an optional
        function to compute next outputs.

        Parameters:
            name (str): The name of the clause.
            script (CScript): The Script associated with the clause.
            arg_specs (List[Tuple[str, ArgType]]): Specifications for the clause's arguments.
            next_outputs_fn (Optional[Callable]): An optional function to compute the next outputs based on
                the clause's arguments and the current contract state (defaults to EMPTY_STATE for stateless).
                The function can either return a list of clause outputs, or a CTV template.
        """

        super().__init__(name, script)
        self.arg_specs = arg_specs

        self.next_outputs_fn = next_outputs_fn

    def next_outputs(self, args: dict, state: ContractState = EMPTY_STATE) -> Union[List[ClauseOutput], CTransaction]:
        """
        Computes the outputs produced by the clause, based on the clause arguments and the contract state.

        Parameters:
            args (dict): The arguments to the clause.
            state (ContractState): The current state of the contract. Defaults to EMPTY_STATE for stateless contracts.

        Returns:
            Union[List[ClauseOutput], CTransaction]: The outputs generated by the clause, or a CTV template.
        """

        if self.next_outputs_fn is not None:
            return self.next_outputs_fn(args, state)
        else:
            return []

    def stack_elements_from_args(self, args: dict) -> List[bytes]:
        """
        Computes the stack elements by serializing the arguments based on the type specified in the
        specifications of the clause's arguments.

        Parameters:
            args (dict): The arguments to be serialized.

        Returns:
            List[bytes]: The list of witness stack elements.

        Raises:
            ValueError: If an argument specified in `arg_specs` is missing from `args`.
        """

        result: List[bytes] = []
        for arg_name, arg_cls in self.arg_specs:
            if arg_name not in args:
                raise ValueError(f"Missing argument: {arg_name}")
            arg_value = args[arg_name]

            result.extend(arg_cls.serialize_to_wit(arg_value))

        return result

    def args_from_stack_elements(self, elements: List[bytes]) -> dict:
        """
        Decodes the elements of a witness stack to compute the clause arguments, based on their
        specifications.

        Parameters:
            elements (List[bytes]): The witness stack elements.

        Returns:
            Dict: The arguments of the clause, decoded from the witness stack elements.

        Raises:
            ValueError: If the decoding based on `arg_specs` fails.
        """

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


Tapleaf = Tuple[str, Union[CScript, bytes]]
TaptreeDescription = List['TaptreeDescription']


class AugmentedP2TR(AbstractContract):
    """
    An abstract class representing a Pay-to-Taproot script with some embedded data.
    While the exact script can only be produced once the embedded data is known,
    the scripts and the "naked internal key" are decided in advance.
    """

    def __init__(self, naked_internal_pubkey: bytes):
        assert len(naked_internal_pubkey) == 32

        self.naked_internal_pubkey = naked_internal_pubkey

    def get_scripts(self) -> TaptreeDescription:
        raise NotImplementedError("This must be implemented in subclasses")

    def get_taptree_merkle_root(self) -> bytes:
        # use dummy data, since it doesn't affect the merkle root
        return self.get_tr_info(b'\0'*32).merkle_root

    def get_tr_info(self, data: bytes) -> TaprootInfo:
        internal_pubkey, _ = tweak_embed_data(self.naked_internal_pubkey, data)

        return script.taproot_construct(internal_pubkey, self.get_scripts())

    def __repr__(self):
        return f"{self.__class__.__name__}(naked_internal_pubkey={self.naked_internal_pubkey.hex()}. Contracts's data: {self.data})"


class SimpleP2TR(AugmentedP2TR):
    """
    A simple Pay-to-Taproot contract with an optional taptree.
    Useful for creating basic P2TR outputs without defining a full contract class.
    """

    def __init__(self, pubkey: bytes, taptree: TaptreeDescription = []):
        """
        Initializes a SimpleP2TR contract.

        Parameters:
            pubkey (bytes): The 32-byte public key.
            taptree (TaptreeDescription): The taptree description. Defaults to [] for keypath-only spend.
        """
        assert len(pubkey) == 32
        super().__init__(pubkey)
        self.taptree = taptree

    def get_scripts(self) -> TaptreeDescription:
        return self.taptree


StandardTaptreeDescription = Union[StandardClause, List['StandardTaptreeDescription']]


# converts a StandardTaptreeDescription to a TaptreeDescription, preserving the structure
def _normalize_standard_taptree_description(std_tree: StandardTaptreeDescription) -> TaptreeDescription:
    if isinstance(std_tree, list):
        if len(std_tree) != 2:
            raise ValueError("A TapBranch must have exactly two children")
        return [_normalize_standard_taptree_description(el) for el in std_tree]
    else:
        # std_tree is actually a single StandardClause
        return [(std_tree.name, std_tree.script)]


# returns a flattenet list of StandardClause
def _flatten_standard_taptree_description(std_tree: StandardTaptreeDescription) -> List[StandardClause]:
    if isinstance(std_tree, list):
        if len(std_tree) != 2:
            raise ValueError("A TapBranch must have exactly two children")
        return [item for subtree in std_tree for item in _flatten_standard_taptree_description(subtree)]
    else:
        # std_tree is a single clause
        return [std_tree]


class StandardAugmentedP2TR(AugmentedP2TR, ABC):
    """
    An AugmentedP2TR where all the transitions are given by a StandardClause.
    """

    State: Optional[Type[ContractState]] = None
    """
    The State class for this contract, or None for stateless contracts.
    Subclasses with state should override this with their ContractState subclass.
    """

    def __init__(self, naked_internal_pubkey: bytes, standard_taptree: StandardTaptreeDescription):
        super().__init__(naked_internal_pubkey)
        self.standard_taptree = standard_taptree
        self.clauses = _flatten_standard_taptree_description(standard_taptree)
        self._clauses_dict = {clause.name: clause for clause in self.clauses}

    def get_scripts(self) -> TaptreeDescription:
        return _normalize_standard_taptree_description(self.standard_taptree)

    def decode_wit_stack(self, data: bytes, stack_elems: List[bytes]) -> Tuple[str, dict]:
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
