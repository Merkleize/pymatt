from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Optional, Tuple, Union

from .argtypes import ArgType
from .btctools import script
from .btctools.key import tweak_add_pubkey
from .btctools.messages import CTransaction
from .btctools.script import OP_1, CScript, TaprootInfo
from .btctools.segwit_addr import encode_segwit_address


class AbstractContract:
    pass


class ClauseOutputAmountBehaviour(Enum):
    PRESERVE_OUTPUT = 0  # The output should be at least as large as the input
    IGNORE_OUTPUT = 1  # The output amount is not checked
    DEDUCT_OUTPUT = 1  # The output amount is subtracted from the input


@dataclass
class ClauseOutput:
    n: Optional[int]
    next_contract: AbstractContract  # only StandardP2TR and StandardAugmentedP2TR are supported so far
    next_data: Optional[bytes] = None  # only meaningful if c is augmented
    next_amount: ClauseOutputAmountBehaviour = ClauseOutputAmountBehaviour.PRESERVE_OUTPUT

    def __repr__(self):
        return f"ClauseOutput(n={self.n}, next_contract={self.next_contract}, next_data={self.next_data}, next_amount={self.next_amount})"


class Clause:
    def __init__(self, name: str, script: CScript):
        self.name = name
        self.script = script

    def stack_elements_from_args(self, args: dict) -> List[bytes]:
        raise NotImplementedError

    def next_outputs(self, args: dict) -> List[ClauseOutput]:
        raise NotImplementedError

    def args_from_stack_elements(self, elements: List[bytes]) -> dict:
        raise NotImplementedError

    def __repr__(self):
        return f"<Clause(name={self.name}, script={self.script})>"


# A StandardClause encodes simple scripts where the witness is exactly
# a list of arguments, always in the same order, and each is either
# an integer or a byte array.
# Other types of generic treatable clauses could be defined (for example, a MiniscriptClause).
# Moreover, it specifies a function that converts the arguments of the clause, to the data of the next output.
class StandardClause(Clause):
    def __init__(self, name: str, script: CScript, arg_specs: List[Tuple[str, ArgType]], next_output_fn: Optional[Callable[[dict], Union[List[ClauseOutput], CTransaction]]] = None):
        super().__init__(name, script)
        self.arg_specs = arg_specs

        self.next_outputs_fn = next_output_fn



    def next_outputs(self, args: dict) -> Union[List[ClauseOutput], CTransaction]:
        if self.next_outputs_fn is not None:
            return self.next_outputs_fn(args)
        else:
            return []

    def stack_elements_from_args(self, args: dict) -> List[bytes]:
        result: List[bytes] = []
        for arg_name, arg_cls in self.arg_specs:
            if arg_name not in args:
                raise ValueError(f"Missing argument: {arg_name}")
            arg_value = args[arg_name]

            result.extend(arg_cls.serialize_to_wit(arg_value))

        return result

    def args_from_stack_elements(self, elements: List[bytes]) -> dict:
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


class P2TR(AbstractContract):
    """
    A class representing a Pay-to-Taproot script.
    """

    def __init__(self, internal_pubkey: bytes, scripts: TaptreeDescription):
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

    def get_scripts(self) -> TaptreeDescription:
        raise NotImplementedError("This must be implemented in subclasses")

    def get_taptree_merkle_root(self) -> bytes:
        # use dummy data, since it doesn't affect the merkle root
        return self.get_tr_info(b'\0'*32).merkle_root

    def get_tr_info(self, data: bytes) -> TaprootInfo:
        assert len(data) == 32

        internal_pubkey, _ = tweak_add_pubkey(self.naked_internal_pubkey, data)

        return script.taproot_construct(internal_pubkey, self.get_scripts())

    def __repr__(self):
        return f"{self.__class__.__name__}(naked_internal_pubkey={self.naked_internal_pubkey.hex()}. Contracts's data: {self.data})"


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


class StandardP2TR(P2TR):
    """
    A StandardP2TR where all the transitions are given by a StandardClause.
    """

    def __init__(self, internal_pubkey: bytes, standard_taptree: StandardTaptreeDescription):
        super().__init__(internal_pubkey, _normalize_standard_taptree_description(standard_taptree))
        self.standard_taptree = standard_taptree
        self.clauses = _flatten_standard_taptree_description(standard_taptree)
        self._clauses_dict = {clause.name: clause for clause in self.clauses}

    def get_scripts(self) -> List[Tuple[str, CScript]]:
        return list(map(lambda clause: (clause.name, clause.script), self.clauses))

    def decode_wit_stack(self, stack_elems: List[bytes]) -> Tuple[str, dict]:
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
