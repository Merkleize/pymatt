from typing import Any, List, Tuple
from abc import ABC, abstractmethod

from .merkle import MerkleProof
from .utils import encode_wit_element, vch2bn


class ArgType(ABC):
    """
    Abstract base class for argument types in script serialization and deserialization.

    Subclasses implements the serialization and deserialization of argument used in
    contract clauses.

    Methods:
        serialize_to_wit(self, value: Any) -> List[bytes]:
            Serializes the provided value into a format suitable for inclusion
            in a witness stack. This method must be overridden in subclasses.

            Args:
                value: The value to be serialized. The type of this value depends
                       on the specific implementation in the subclass.

            Returns:
                A list of one or more witness arguments, serialized in the format of
                the witness stack.

        deserialize_from_wit(self, wit_stack: List[bytes]) -> Tuple[int, Any]:
            Deserializes data from a witness stack into a Python object. This
            method must be overridden in subclasses.

            Args:
                wit_stack: A list of bytes representing the witness stack. This is not
                           the full witness stack, as it does not includes the elements
                           that were already consumed.

            Returns:
                A tuple containing two elements:
                - An int indicating the number of elements consumed from the wit_stack.
                - The deserialized value as a Python object. The exact type of this
                  object depends on the subclass implementation.
    """
    @abstractmethod
    def serialize_to_wit(self, value: Any) -> List[bytes]:
        raise NotImplementedError()

    @abstractmethod
    def deserialize_from_wit(self, wit_stack: List[bytes]) -> Tuple[int, Any]:
        raise NotImplementedError()


class IntType(ArgType):
    def serialize_to_wit(self, value: int) -> List[bytes]:
        return [encode_wit_element(value)]

    def deserialize_from_wit(self, wit_stack: List[bytes]) -> Tuple[int, int]:
        return 1, vch2bn(wit_stack[0])


class BytesType(ArgType):
    def serialize_to_wit(self, value: int) -> List[bytes]:
        return [encode_wit_element(value)]

    def deserialize_from_wit(self, wit_stack: List[bytes]) -> Tuple[int, bytes]:
        return 1, wit_stack[0]


class SignerType(BytesType):
    """
    This is a special type for arguments that represent signatures in tapscripts.
    It is encoded as bytes, but labeling it allows the ContractManager to get the correct
    signatures by calling SchnorrSigner object instances.
    """

    def __init__(self, pubkey: bytes):
        if len(pubkey) != 32:
            raise ValueError("pubkey must be an x-only pubkey")
        self.pubkey = pubkey


class MerkleProofType(ArgType):
    def __init__(self, depth: int):
        self.depth = depth

    def serialize_to_wit(self, value: MerkleProof) -> List[bytes]:
        return value.to_wit_stack()

    def deserialize_from_wit(self, wit_stack: List[bytes]) -> Tuple[int, MerkleProof]:
        n_proof_elements = 2 * self.depth + 1
        if len(wit_stack) < n_proof_elements:
            raise ValueError("Witness stack too short")
        return (n_proof_elements, MerkleProof.from_wit_stack(wit_stack[:n_proof_elements]))
