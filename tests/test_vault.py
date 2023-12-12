from io import TextIOWrapper
import pytest

from examples.vault.vault_contracts import Vault

from matt.btctools import key
from matt.btctools.auth_proxy import AuthServiceProxy, JSONRPCException
from matt.btctools.messages import CTxOut
from matt.contracts import OpaqueP2TR
from matt.manager import ContractManager, SchnorrSigner
from matt.utils import format_tx_markdown, make_ctv_template

from test_utils import mine_blocks


unvault_priv_key = key.ExtendedKey.deserialize(
    "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN")
recover_priv_key = key.ExtendedKey.deserialize(
    "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ")


def test_vault_recover(manager: ContractManager, report_file: TextIOWrapper):
    V = Vault(None, 10, recover_priv_key.pubkey[1:], unvault_priv_key.pubkey[1:])

    amount = 20_000

    V_inst = manager.fund_instance(V, amount)

    out_instances = V_inst("recover", out_i=0)

    out: CTxOut = V_inst.spending_tx.vout[0]

    assert out.nValue == amount
    assert out.scriptPubKey == OpaqueP2TR(recover_priv_key.pubkey[1:]).get_tr_info().scriptPubKey

    report_file.write(format_tx_markdown(V_inst.spending_tx, "Recovery from vault, 1 input [NoRecoveryAuth]"))

    assert len(out_instances) == 0


def test_vault_trigger_and_recover(manager: ContractManager, report_file: TextIOWrapper):
    locktime = 10
    V = Vault(None, locktime, recover_priv_key.pubkey[1:], unvault_priv_key.pubkey[1:])

    signer = SchnorrSigner(unvault_priv_key)

    amount = 4999990000

    V_inst = manager.fund_instance(V, amount)

    ctv_tmpl = make_ctv_template([
        ("bcrt1qqy0kdmv0ckna90ap6efd6z39wcdtpfa3a27437", 4999990000),
        ("bcrt1qpnpjyzkfe7n5eppp2ktwpvuxfw5qfn2zjdum83", 4999990000),
        ("bcrt1q6vqduw24yjjll6nfkxlfy2twwt52w58tnvnd46", 4999990000),
    ], nSequence=locktime)

    [U_inst] = V_inst("trigger", signer=signer,
                      out_i=0, ctv_hash=ctv_tmpl.get_standard_template_hash(0))

    report_file.write(format_tx_markdown(V_inst.spending_tx, "Trigger [3 vault inputs]"))

    out_instances = U_inst("recover", out_i=0)

    assert len(out_instances) == 0

    report_file.write(format_tx_markdown(U_inst.spending_tx, "Recovery from trigger"))


def test_vault_trigger_and_withdraw(rpc: AuthServiceProxy, manager: ContractManager, report_file: TextIOWrapper):
    locktime = 10
    V = Vault(None, locktime, recover_priv_key.pubkey[1:], unvault_priv_key.pubkey[1:])

    signer = SchnorrSigner(unvault_priv_key)

    amount = 4999990000

    V_inst = manager.fund_instance(V, amount)

    ctv_tmpl = make_ctv_template([
        ("bcrt1qqy0kdmv0ckna90ap6efd6z39wcdtpfa3a27437", 1666663333),
        ("bcrt1qpnpjyzkfe7n5eppp2ktwpvuxfw5qfn2zjdum83", 1666663333),
        ("bcrt1q6vqduw24yjjll6nfkxlfy2twwt52w58tnvnd46", 1666663334),
    ], nSequence=locktime)

    [U_inst] = V_inst("trigger", signer=signer,
                      out_i=0, ctv_hash=ctv_tmpl.get_standard_template_hash(0))

    report_file.write(format_tx_markdown(V_inst.spending_tx, "Trigger [3 vault inputs]"))

    spend_tx, _ = manager.get_spend_tx(
        (U_inst, "withdraw", {"ctv_hash": ctv_tmpl.get_standard_template_hash(0)})
    )

    # TODO: get_spend_wit does not fill the transaction
    # according to the template (which the manager doesn't know)
    # Figure out a better way to let the framework handle this
    spend_tx.wit.vtxinwit = [manager.get_spend_wit(
        U_inst,
        "withdraw",
        {"ctv_hash": ctv_tmpl.get_standard_template_hash(0)}
    )]

    spend_tx.nVersion = ctv_tmpl.nVersion
    spend_tx.nLockTime = ctv_tmpl.nLockTime
    spend_tx.vin[0].nSequence = ctv_tmpl.vin[0].nSequence  # we assume only 1 input
    spend_tx.vout = ctv_tmpl.vout

    with pytest.raises(JSONRPCException, match='non-BIP68-final'):
        manager.spend_and_wait(U_inst, spend_tx)

    mine_blocks(rpc, locktime - 1)

    manager.spend_and_wait(U_inst, spend_tx)

    report_file.write(format_tx_markdown(U_inst.spending_tx, "Withdraw [3 outputs]"))


def test_vault_trigger_with_revault_and_withdraw(rpc: AuthServiceProxy, manager: ContractManager, report_file: TextIOWrapper):
    # get coins on 3 different Vaults, then trigger with partial withdrawal
    # one of the vault uses "trigger_with_revault", the others us normal "trigger"

    locktime = 10
    amount = 4999990000

    V = Vault(None, locktime, recover_priv_key.pubkey[1:], unvault_priv_key.pubkey[1:])

    V_inst_1 = manager.fund_instance(V, amount)
    V_inst_2 = manager.fund_instance(V, amount)
    V_inst_3 = manager.fund_instance(V, amount)

    ctv_tmpl = make_ctv_template([
        ("bcrt1qqy0kdmv0ckna90ap6efd6z39wcdtpfa3a27437", 4999990000),
        ("bcrt1qpnpjyzkfe7n5eppp2ktwpvuxfw5qfn2zjdum83", 4999990000),
        ("bcrt1q6vqduw24yjjll6nfkxlfy2twwt52w58tnvnd46", 2999990000),
    ], nSequence=locktime)
    ctv_hash = ctv_tmpl.get_standard_template_hash(nIn=0)

    revault_amount = 3*amount - sum(out.nValue for out in ctv_tmpl.vout)

    spends = [
        (V_inst_1, "trigger_and_revault", {"out_i": 0, "revault_out_i": 1, "ctv_hash": ctv_hash}),
        (V_inst_2, "trigger", {"out_i": 0, "ctv_hash": ctv_hash}),
        (V_inst_3, "trigger", {"out_i": 0, "ctv_hash": ctv_hash}),
    ]

    spend_tx, sighashes = manager.get_spend_tx(spends, output_amounts={1: revault_amount})

    spend_tx.wit.vtxinwit = []

    sigs = [key.sign_schnorr(unvault_priv_key.privkey, sighash) for sighash in sighashes]

    for i, (V_inst_i, action, args) in enumerate(spends):
        spend_tx.wit.vtxinwit.append(manager.get_spend_wit(
            V_inst_i,
            action,
            {**args, "sig": sigs[i]}
        ))

    [U_inst] = manager.spend_and_wait([V_inst_1, V_inst_2, V_inst_3], spend_tx)

    report_file.write(format_tx_markdown(spend_tx, "Trigger (with revault) [3 vault inputs]"))

    spend_tx, _ = manager.get_spend_tx(
        (U_inst, "withdraw", {"ctv_hash": ctv_tmpl.get_standard_template_hash(0)})
    )

    # TODO: get_spend_wit does not fill the transaction
    # according to the template (which the manager doesn't know)
    # Figure out a better way to let the framework handle this
    spend_tx.wit.vtxinwit = [manager.get_spend_wit(
        U_inst,
        "withdraw",
        {"ctv_hash": ctv_tmpl.get_standard_template_hash(0)}
    )]

    spend_tx.nVersion = ctv_tmpl.nVersion
    spend_tx.nLockTime = ctv_tmpl.nLockTime
    spend_tx.vin[0].nSequence = ctv_tmpl.vin[0].nSequence  # we assume only 1 input
    spend_tx.vout = ctv_tmpl.vout

    mine_blocks(rpc, locktime - 1)

    manager.spend_and_wait(U_inst, spend_tx)

    report_file.write(format_tx_markdown(U_inst.spending_tx, "Withdraw (3 outputs)"))
