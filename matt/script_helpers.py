

from typing import Optional, Union
from matt import CCV_FLAG_CHECK_INPUT
from matt.btctools.script import OP_2DROP, OP_2DUP, OP_2OVER, OP_3DUP, OP_CAT, OP_CHECKCONTRACTVERIFY, OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_DUP, OP_FROMALTSTACK, OP_PICK, OP_SHA256, OP_TOALTSTACK, CScript
from matt.contracts import StandardAugmentedP2TR, StandardP2TR


# Duplicates the last n elements of the stack
def dup(n: int = 1) -> CScript:
    assert n >= 1
    if n == 1:
        return CScript([OP_DUP])
    elif n == 2:
        return CScript([OP_2DUP])
    elif n == 3:
        return CScript([OP_3DUP])
    elif n == 4:
        return CScript([OP_2OVER, OP_2OVER])
    else:
        # generic, unoptimized solution
        # TODO: can we find an optimal script for every n?
        return CScript([n - 1, OP_PICK] * n)


# Drops n elements from the stack
def drop(n: int = 1) -> CScript:
    assert n >= 0

    return CScript([OP_2DROP]*(n // 2) + [OP_DROP] * (n % 2))


# x_0, x_1, ..., x_{n-1} -- sha256(x_0 || x_1), sha256(x_2 || x_3), ...
# if n is odd, the last element is copied unchanged
def reduce_merkle_layer(n: int) -> CScript:
    assert n >= 1

    if n == 1:
        return CScript([])
    elif n == 2:
        return CScript([OP_CAT, OP_SHA256])
    if n % 2 == 1:
        return CScript([OP_TOALTSTACK, *reduce_merkle_layer(n-1), OP_FROMALTSTACK])
    else:
        # compute the last pair, reduce to the case with one less pair
        return CScript([OP_CAT, OP_SHA256, OP_TOALTSTACK, *reduce_merkle_layer(n-2), OP_FROMALTSTACK])


# x_0, x_1, ..., x_{n - 1} -- x_0, x_1, ..., x_{n - 1} root
# where root is the root of the merkle tree computed on x_0, ... x_{n - 1}
# NOTE: leaves are not hashed here.
def merkle_root(n_leaves: int) -> CScript:
    assert n_leaves >= 1

    ret = []
    # compute layer by layer, from the bottom up to the root
    while n_leaves > 1:
        ret.extend(reduce_merkle_layer(n_leaves))
        n_leaves = (n_leaves + 1) // 2
    return CScript(ret)


# data --
# TODO: should we pass the contract instance (typically 'self') instead of the pubkey?
def check_input_contract(index: int = -1, pubkey: Optional[bytes] = None) -> CScript:
    assert index >= -1
    assert pubkey is None or len(pubkey) == 32
    return CScript([
        index,
        0 if pubkey is None else pubkey,
        -1,
        CCV_FLAG_CHECK_INPUT,
        OP_CHECKCONTRACTVERIFY
    ])


# data --
def check_output_contract(out_contract: Union[StandardP2TR, StandardAugmentedP2TR], index: int = -1, pubkey: Optional[bytes] = None) -> CScript:
    assert index >= -1
    assert pubkey is None or len(pubkey) == 32
    return CScript([
        index,
        0 if pubkey is None else pubkey,
        out_contract.get_taptree_merkle_root(),
        0,
        OP_CHECKCONTRACTVERIFY
    ])


# like the older() fragment in miniscript
def older(n: int) -> CScript:
    assert 1 <= n < 2**31

    return CScript([n, OP_CHECKSEQUENCEVERIFY, OP_DROP])
