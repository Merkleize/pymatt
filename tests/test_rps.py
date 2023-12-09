import pytest

from examples.rps.rps_contracts import DEFAULT_STAKE, RPS, RPSGameS0

from matt import ContractManager, SchnorrSigner
from matt.btctools import key
from matt.btctools.auth_proxy import JSONRPCException


import random

random.seed(0)


alice_key = key.ExtendedKey.deserialize("tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN")
bob_key = key.ExtendedKey.deserialize("tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ")

moves = {
    "rock": 0,
    "paper": 1,
    "scissors": 2
}

alice_signer = SchnorrSigner(alice_key)
bob_signer = SchnorrSigner(bob_key)


def test_rps(manager: ContractManager):
    m_a = moves["rock"]

    r_a = random.randbytes(32)
    c_a = RPS.calculate_hash(m_a, r_a)

    S0 = RPSGameS0(alice_key.pubkey[1:], bob_key.pubkey[1:], c_a)
    S0_inst = manager.fund_instance(S0, DEFAULT_STAKE*2)

    # Bob's move
    m_b = moves["paper"]

    [S1_inst] = S0_inst("bob_move", signer=bob_signer, m_b=m_b)

    # cheating attempt
    with pytest.raises(JSONRPCException, match='Script failed an OP_EQUALVERIFY operation'):
        S1_inst("alice_wins", m_a = m_a, m_b = m_b, r_a = r_a)

    # cheat a bit less
    with pytest.raises(JSONRPCException, match='Script failed an OP_EQUALVERIFY operation'):
        S1_inst("tie", m_a = m_a, m_b = m_b, r_a = r_a)

    # correct adjudication
    S1_inst("bob_wins", m_a = m_a, m_b = m_b, r_a = r_a)

