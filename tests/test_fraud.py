from examples.fraud.fraud_contracts import G256_S0, G256_S1, G256_S2, Compute2x

from matt.btctools.common import sha256
from matt.btctools.messages import CTxOut
from matt.hub.fraud import Bisect_1, Bisect_2, Leaf
from matt.manager import ContractManager, SchnorrSigner
from matt.merkle import MerkleTree, is_power_of_2
from matt.btctools import key
from matt.utils import encode_wit_element


AMOUNT = 20_000
alice_key = key.ExtendedKey.deserialize(
    "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN")
bob_key = key.ExtendedKey.deserialize(
    "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ")

# TODO: make outputs that sends to Alice/Bob, instead of using burn addresses :P


def test_leaf_reveal_alice(manager: ContractManager):
    L = Leaf(alice_key.pubkey[1:], bob_key.pubkey[1:], Compute2x)

    x_start = 347
    x_end_alice = 2 * x_start
    x_end_bob = 2 * x_start - 1  # some wrong value

    h_start = sha256(encode_wit_element(x_start))
    h_end_alice = sha256(encode_wit_element(x_end_alice))
    h_end_bob = sha256(encode_wit_element(x_end_bob))

    data = [h_start, h_end_alice, h_end_bob]
    mt = MerkleTree(data)

    L_inst = manager.fund_instance(L, AMOUNT, data=mt.root)
    L_inst.data_expanded = data

    outputs = [
        CTxOut(
            nValue=AMOUNT,
            scriptPubKey=bytes([0, 0x20, *[0x42]*32])
        )
    ]

    out_instances = L_inst("alice_reveal",
                           signer=SchnorrSigner(alice_key),
                           outputs=outputs,
                           x=x_start,
                           h_y_b=h_end_bob)

    assert len(out_instances) == 0


def test_leaf_reveal_bob(manager: ContractManager):
    L = Leaf(alice_key.pubkey[1:], bob_key.pubkey[1:], Compute2x)

    x_start = 347
    x_end_alice = 2 * x_start - 1  # some wrong value
    x_end_bob = 2 * x_start

    h_start = sha256(encode_wit_element(x_start))
    h_end_alice = sha256(encode_wit_element(x_end_alice))
    h_end_bob = sha256(encode_wit_element(x_end_bob))

    data = [h_start, h_end_alice, h_end_bob]
    mt = MerkleTree(data)

    L_inst = manager.fund_instance(L, AMOUNT, data=mt.root)
    L_inst.data_expanded = data

    outputs = [
        CTxOut(
            nValue=AMOUNT,
            scriptPubKey=bytes([0, 0x20, *[0x42]*32])
        )
    ]

    out_instances = L_inst("bob_reveal",
                           signer=SchnorrSigner(bob_key),
                           outputs=outputs,
                           x=x_start,
                           h_y_a=h_end_alice)

    assert len(out_instances) == 0


def test_fraud_proof_full(manager: ContractManager):
    alice_trace = [2, 4, 8, 16, 32, 64, 127, 254, 508]
    bob_trace = [2, 4, 8, 16, 32, 64, 128, 256, 512]

    # TODO: the contract instance should be able to keep track of the data contained

    assert alice_trace[0] == bob_trace[0] and len(alice_trace) == len(bob_trace)

    n = len(alice_trace) - 1  # the trace has n + 1 entries

    assert is_power_of_2(n)

    h_a = [sha256(encode_wit_element(x)) for x in alice_trace]
    h_b = [sha256(encode_wit_element(x)) for x in bob_trace]

    def t_from_trace(trace, i, j):
        assert len(trace) > j
        assert 0 <= i < n
        assert i <= j < n

        assert j >= i and is_power_of_2(j - i + 1)

        m = (j - i + 1) // 2

        if i == j:
            return sha256(trace[i] + trace[i + 1])
        else:
            return sha256(trace[i] + trace[j + 1] + t_from_trace(trace, i, i + m - 1) + t_from_trace(trace, i + m, j))

    def t_node_a(i, j) -> bytes:
        return t_from_trace(h_a, i, j)

    def t_node_b(i, j) -> bytes:
        return t_from_trace(h_b, i, j)

    x = 2
    y = alice_trace[-1]
    z = bob_trace[-1]

    assert z == 2 * 256  # Bob is saying the truth

    alice_signer = SchnorrSigner(alice_key)
    bob_signer = SchnorrSigner(bob_key)

    # Game starts, the UTXO is funded
    G = G256_S0(alice_key.pubkey[1:], bob_key.pubkey[1:])

    inst = manager.fund_instance(G, AMOUNT)

    # Bob chooses its input
    [inst] = inst('choose', signer=bob_signer, x=x)

    assert isinstance(inst.contract, G256_S1)

    t_a = t_node_a(0, n - 1)  # trace root according to Alice
    t_b = t_node_b(0, n - 1)  # trace root according to Bob

    # Alice reveals her answer
    [inst] = inst('reveal', signer=alice_signer,
                  y=y,
                  t_a=t_a,
                  sha256_x=sha256(encode_wit_element(x))
                  )
    inst.data = MerkleTree([t_a, sha256(encode_wit_element(y)), sha256(encode_wit_element(x))]).root

    assert isinstance(inst.contract, G256_S2)

    # Bob disagrees and starts the challenge
    [inst] = inst('start_challenge', signer=bob_signer,
                  t_a=t_a,
                  sha256_y=sha256(encode_wit_element(y)),
                  sha256_x=sha256(encode_wit_element(x)),
                  z=z,
                  t_b=t_b
                  )

    # inst now represents a step in the bisection protocol corresponding to the root of the computation

    assert isinstance(inst.contract, Bisect_1)
    assert inst.contract.i == 0 and inst.contract.j == 7
    i, j = inst.contract.i, inst.contract.j
    m = (j - i + 1) // 2
    [inst] = inst('alice_reveal', signer=alice_signer,
                  h_i=h_a[i],
                  h_j_plus_1_a=h_a[j + 1],
                  h_j_plus_1_b=h_b[j + 1],
                  t_i_j_a=t_node_a(i, j),
                  t_i_j_b=t_node_b(i, j),
                  h_i_plus_m_a=h_a[i + m],
                  t_left_a=t_node_a(i, i + m - 1),
                  t_right_a=t_node_a(i + m, j)
                  )

    assert isinstance(inst.contract, Bisect_2)
    assert inst.contract.i == 0 and inst.contract.j == 7

    [inst] = inst('bob_reveal_right', signer=bob_signer,
                  h_i=h_a[i],
                  h_j_plus_1_a=h_a[j + 1],
                  h_j_plus_1_b=h_b[j + 1],
                  t_i_j_a=t_node_a(i, j),
                  t_i_j_b=t_node_b(i, j),
                  h_i_plus_m_a=h_a[i + m],
                  t_left_a=t_node_a(i, i + m - 1),
                  t_right_a=t_node_a(i + m, j),
                  h_i_plus_m_b=h_b[i + m],
                  t_left_b=t_node_b(i, i + m - 1),
                  t_right_b=t_node_b(i + m, j),
                  )

    assert isinstance(inst.contract, Bisect_1)
    i, j = inst.contract.i, inst.contract.j
    m = (j - i + 1) // 2
    assert i == 4 and j == 7

    # Bisection repeats on the node covering from index 4 to index 7
    [inst] = inst('alice_reveal', signer=alice_signer,
                  h_i=h_a[i],
                  h_j_plus_1_a=h_a[j + 1],
                  h_j_plus_1_b=h_b[j + 1],
                  t_i_j_a=t_node_a(i, j),
                  t_i_j_b=t_node_b(i, j),
                  h_i_plus_m_a=h_a[i + m],
                  t_left_a=t_node_a(i, i + m - 1),
                  t_right_a=t_node_a(i + m, j)
                  )

    assert isinstance(inst.contract, Bisect_2)
    assert inst.contract.i == 4 and inst.contract.j == 7

    [inst] = inst('bob_reveal_left', signer=bob_signer,
                  h_i=h_a[i],
                  h_j_plus_1_a=h_a[j + 1],
                  h_j_plus_1_b=h_b[j + 1],
                  t_i_j_a=t_node_a(i, j),
                  t_i_j_b=t_node_b(i, j),
                  h_i_plus_m_a=h_a[i + m],
                  t_left_a=t_node_a(i, i + m - 1),
                  t_right_a=t_node_a(i + m, j),
                  h_i_plus_m_b=h_b[i + m],
                  t_left_b=t_node_b(i, i + m - 1),
                  t_right_b=t_node_b(i + m, j),
                  )

    assert isinstance(inst.contract, Bisect_1)
    i, j = inst.contract.i, inst.contract.j
    m = (j - i + 1) // 2
    assert i == 4 and j == 5

    # Bisection repeats on the node covering from index 4 to index 5 (last bisection step)

    [inst] = inst('alice_reveal', signer=alice_signer,
                  h_i=h_a[i],
                  h_j_plus_1_a=h_a[j + 1],
                  h_j_plus_1_b=h_b[j + 1],
                  t_i_j_a=t_node_a(i, j),
                  t_i_j_b=t_node_b(i, j),
                  h_i_plus_m_a=h_a[i + m],
                  t_left_a=t_node_a(i, i + m - 1),
                  t_right_a=t_node_a(i + m, j)
                  )

    assert isinstance(inst.contract, Bisect_2)
    assert inst.contract.i == 4 and inst.contract.j == 5

    [inst] = inst('bob_reveal_right', signer=bob_signer,
                  h_i=h_a[i],
                  h_j_plus_1_a=h_a[j + 1],
                  h_j_plus_1_b=h_b[j + 1],
                  t_i_j_a=t_node_a(i, j),
                  t_i_j_b=t_node_b(i, j),
                  h_i_plus_m_a=h_a[i + m],
                  t_left_a=t_node_a(i, i + m - 1),
                  t_right_a=t_node_a(i + m, j),
                  h_i_plus_m_b=h_b[i + m],
                  t_left_b=t_node_b(i, i + m - 1),
                  t_right_b=t_node_b(i + m, j),
                  )

    # We reached a leaf. Only who was doubling correctly can withdraw

    assert isinstance(inst.contract, Leaf)

    assert alice_trace[5] == bob_trace[5] and alice_trace[6] != bob_trace[6]

    outputs = [
        CTxOut(
            nValue=AMOUNT,
            scriptPubKey=bytes([0, 0x20, *[0x42]*32])
        )
    ]
    out_instances = inst("bob_reveal",
                         signer=SchnorrSigner(bob_key),
                         outputs=outputs,
                         x=bob_trace[5],
                         h_y_a=h_a[6])

    assert len(out_instances) == 0
