from btctools import script, key
from btctools.script import CScript, CTxOut, TaprootInfo

# Flags for OP_CHECKCONTRACTVERIFY
CCV_FLAG_CHECK_INPUT: int = 1
CCV_FLAG_IGNORE_OUTPUT_AMOUNT: int = 2


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


class Clause:
    def __init__(self, name: str, script: CScript):
        self.name = name
        self.script = script

    def stack_elements_from_args(self, args: dict) -> list[bytes]:
        raise NotImplementedError

    def args_from_stack_elements(self, elements: list[bytes]) -> dict:
        raise NotImplementedError


StandardType = type[int] | type[bytes]


# A StandardClause encodes simple scripts where the witness is exactly
# a list of arguments, always in the same order, and each is either
# an integer or a byte array.
# Other types of generic treatable clauses could be defined (for example, a MiniscriptClause).
class StandardClause(Clause):
    def __init__(self, name: str, script: CScript, arg_specs: list[tuple[str, StandardType]]):
        super().__init__(name, script)
        self.arg_specs = arg_specs

        for _, arg_cls in self.arg_specs:
            if arg_cls not in [int, bytes]:
                raise ValueError(f"Unsupported type: {arg_cls.__name__}")

    def stack_elements_from_args(self, args: dict) -> list[bytes]:
        result: list[bytes] = []
        for arg_name, arg_cls in self.arg_specs:
            if arg_name not in args:
                raise ValueError(f"Missing argument: {arg_name}")
            arg_value = args[arg_name]
            if type(arg_value) != arg_cls:
                raise ValueError(f"Argument {arg_name} must be of type {arg_cls.__name__}, not {type(arg_value).__name__}")
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


class P2TR:
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

    def get_tx_out(self, value: int) -> CTxOut:
        return CTxOut(
            nValue=value,
            scriptPubKey=self.get_tr_info().scriptPubKey
        )


class AugmentedP2TR:
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

    def get_tx_out(self, value: int, data: bytes) -> CTxOut:
        return CTxOut(nValue=value, scriptPubKey=self.get_tr_info(data).scriptPubKey)


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

    def encode_args(self, clause_name: str, **args: dict) -> list[bytes]:
        return [
            *self._clauses_dict[clause_name].stack_elements_from_args(args),
            self.get_tr_info().leaves[clause_name].script,
            self.get_tr_info().controlblock_for_script_spend(clause_name),
        ]

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

    def encode_args(self, clause_name: str, data: bytes, **args: dict) -> list[bytes]:
        return [
            *self._clauses_dict[clause_name].stack_elements_from_args(args),
            self.get_tr_info(data).leaves[clause_name].script,
            self.get_tr_info(data).controlblock_for_script_spend(clause_name),
        ]

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