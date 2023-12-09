from examples.ram.ram_contracts import RAM

from matt import ContractManager
from matt.btctools.common import sha256
from matt.btctools.messages import CTxOut
from matt.merkle import MerkleTree


AMOUNT = 20_000


def test_withdraw(rpc, manager: ContractManager):
    # tests the "withdraw" clause, that allows spending anywhere as long
    # as a valid Merkle proof is provided
    for size in [8, 16]:
        for leaf_index in [0, 1, 4, size - 2, size - 1]:
            data = [sha256(i.to_bytes(1, byteorder='little')) for i in range(size)]
            mt = MerkleTree(data)

            R_inst = manager.fund_instance(RAM(len(data)), AMOUNT, data=mt.root)

            outputs = [
                CTxOut(
                    nValue=AMOUNT,
                    scriptPubKey=bytes([0, 0x20, *[0x42]*32])
                )
            ]

            out_instances = R_inst("withdraw",
                outputs = outputs,
                merkle_root = mt.root,
                merkle_proof = mt.prove_leaf(leaf_index)
            )

            assert len(out_instances) == 0


def test_write(manager: ContractManager):
    # tests the "write" clause, spending the RAM into a new RAM where a single element is modified
    size = 8
    leaf_index = 5
    new_value = sha256("now this is different".encode())

    data = [sha256(i.to_bytes(1, byteorder='little')) for i in range(size)]
    mt = MerkleTree(data)

    R_inst = manager.fund_instance(RAM(len(data)), AMOUNT, data=mt.root)

    out_instances = R_inst("write",
        merkle_root = mt.root,
        new_value = new_value,
        merkle_proof = mt.prove_leaf(leaf_index)
    )

    assert len(out_instances) == 1

    assert isinstance(out_instances[0].contract, RAM)

    data_modified = data[:leaf_index] + [new_value] + data[leaf_index + 1:]
    mt_modified = MerkleTree(data_modified)

    assert out_instances[0].data == mt_modified.root


def test_write_loop(manager: ContractManager):
    # spend a RAM contract in a chain, modifying one element each time
    size = 8

    data = [sha256(i.to_bytes(1, byteorder='little')) for i in range(size)]

    R_inst = manager.fund_instance(RAM(len(data)), AMOUNT, data=MerkleTree(data).root)

    for i in range(16):
        leaf_index = i % size
        new_value = sha256((100 + i).to_bytes(1, byteorder='little'))

        out_instances = R_inst("write",
            merkle_root = MerkleTree(data).root,
            new_value = new_value,
            merkle_proof = MerkleTree(data).prove_leaf(leaf_index)
        )

        assert len(out_instances) == 1

        R_inst = out_instances[0]
        assert isinstance(R_inst.contract, RAM)

        data = data[:leaf_index] + [new_value] + data[leaf_index + 1:]

        assert R_inst.data == MerkleTree(data).root
