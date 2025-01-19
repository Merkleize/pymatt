from typing import Tuple
import pytest

from examples.vault.minivault_contracts import Vault, Unvaulting

from matt.btctools import key
from matt.btctools.auth_proxy import AuthServiceProxy, JSONRPCException
from matt.btctools.messages import CTxOut
from matt.contracts import OpaqueP2TR
from matt.manager import ContractManager, SchnorrSigner
from matt.utils import format_tx_markdown

from test_utils import mine_blocks


unvault_priv_key = key.ExtendedKey.deserialize(
    "tprv8ZgxMBicQKsPdpwA4vW8DcSdXzPn7GkS2RdziGXUX8k86bgDQLKhyXtB3HMbJhPFd2vKRpChWxgPe787WWVqEtjy8hGbZHqZKeRrEwMm3SN")
recover_priv_key = key.ExtendedKey.deserialize(
    "tprv8ZgxMBicQKsPeDvaW4xxmiMXxqakLgvukT8A5GR6mRwBwjsDJV1jcZab8mxSerNcj22YPrusm2Pz5oR8LTw9GqpWT51VexTNBzxxm49jCZZ")


locktime = 10

MiniVaultSpecs = Tuple[str, Vault]


V_full: MiniVaultSpecs = (
    "MiniVault",
    Vault(None, locktime, recover_priv_key.pubkey[1:], unvault_priv_key.pubkey[1:])
)
V_no_partial_revault: MiniVaultSpecs = (
    "MiniVault [no partial revault]",
    Vault(None, locktime, recover_priv_key.pubkey[1:], unvault_priv_key.pubkey[1:], has_partial_revault=False)
)

V_no_early_recover: MiniVaultSpecs = (
    "MiniVault [no early recover]",
    Vault(None, locktime, recover_priv_key.pubkey[1:], unvault_priv_key.pubkey[1:], has_early_recover=False)
)

V_light: MiniVaultSpecs = (
    "MiniVault [lightweight - no partial revault, no early recover]",
    Vault(None, locktime, recover_priv_key.pubkey[1:], unvault_priv_key.pubkey[1:],
          has_partial_revault=False, has_early_recover=False)
)


@pytest.mark.parametrize("minivault_specs", [V_full])
def test_minivault_recover(minivault_specs: MiniVaultSpecs, manager: ContractManager, report):
    vault_description, vault_contract = minivault_specs

    amount = 20_000

    V_inst = manager.fund_instance(vault_contract, amount)

    out_instances = V_inst("recover")(out_i=0)

    out: CTxOut = V_inst.spending_tx.vout[0]

    assert out.nValue == amount
    assert out.scriptPubKey == OpaqueP2TR(recover_priv_key.pubkey[1:]).get_tr_info().scriptPubKey

    report.write(vault_description, format_tx_markdown(V_inst.spending_tx, "Recovery from vault, 1 input"))

    assert len(out_instances) == 0


@pytest.mark.parametrize("minivault_specs", [V_full, V_no_partial_revault, V_no_early_recover, V_light])
def test_minivault_trigger_and_recover(minivault_specs: MiniVaultSpecs, manager: ContractManager, report):
    vault_description, vault_contract = minivault_specs

    amount = 49999900

    V_inst = manager.fund_instance(vault_contract, amount)

    withdrawal_pk = bytes.fromhex("0981368165440d4fe866f84d75ae53a95b192aa45155735d4cb2a8894b340b8f")

    [U_inst] = V_inst("trigger", signer=SchnorrSigner(unvault_priv_key))(
        out_i=0,
        withdrawal_pk=withdrawal_pk
    )

    report.write(vault_description, format_tx_markdown(V_inst.spending_tx, "Trigger"))

    out_instances = U_inst("recover")(out_i=0)

    assert len(out_instances) == 0

    report.write(vault_description, format_tx_markdown(U_inst.spending_tx, "Recovery from trigger"))


@pytest.mark.parametrize("minivault_specs", [V_full, V_no_partial_revault, V_no_early_recover, V_light])
def test_minivault_trigger_and_withdraw(minivault_specs: MiniVaultSpecs, rpc: AuthServiceProxy, manager: ContractManager, report):
    vault_description, vault_contract = minivault_specs

    signer = SchnorrSigner(unvault_priv_key)

    amount = 49999900

    V_inst = manager.fund_instance(vault_contract, amount)

    withdrawal_pk = bytes.fromhex("0981368165440d4fe866f84d75ae53a95b192aa45155735d4cb2a8894b340b8f")

    [U_inst] = V_inst("trigger", signer=signer)(
        out_i=0,
        withdrawal_pk=withdrawal_pk
    )

    spend_tx, _ = manager.get_spend_tx(
        (U_inst, "withdraw", {"withdrawal_pk": withdrawal_pk})
    )

    spend_tx.wit.vtxinwit = [manager.get_spend_wit(
        U_inst,
        "withdraw",
        {"withdrawal_pk": withdrawal_pk}
    )]

    spend_tx.vin[0].nSequence = locktime

    with pytest.raises(JSONRPCException):
        manager.spend_and_wait(U_inst, spend_tx)

    mine_blocks(rpc, locktime - 1)

    manager.spend_and_wait(U_inst, spend_tx)

    report.write(vault_description, format_tx_markdown(U_inst.spending_tx, "Withdraw"))


@pytest.mark.parametrize("minivault_specs", [V_full, V_no_early_recover])
def test_minivault_trigger_with_revault_and_withdraw(minivault_specs: MiniVaultSpecs, rpc: AuthServiceProxy, manager: ContractManager, report):
    # get coins on 3 different Vaults, then trigger with partial withdrawal
    # one of the vault uses "trigger_with_revault", the others us normal "trigger"

    vault_description, vault_contract = minivault_specs

    amount = 49_999_900

    V_inst_1 = manager.fund_instance(vault_contract, amount)
    V_inst_2 = manager.fund_instance(vault_contract, amount)
    V_inst_3 = manager.fund_instance(vault_contract, amount)

    withdrawal_pk = bytes.fromhex("0981368165440d4fe866f84d75ae53a95b192aa45155735d4cb2a8894b340b8f")
    revault_amount = 20_000_000

    spends = [
        (V_inst_1, "trigger_and_revault", {"out_i": 0, "revault_out_i": 1, "withdrawal_pk": withdrawal_pk}),
        (V_inst_2, "trigger", {"out_i": 0, "withdrawal_pk": withdrawal_pk}),
        (V_inst_3, "trigger", {"out_i": 0, "withdrawal_pk": withdrawal_pk}),
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

    [U_inst, V_revault_inst] = manager.spend_and_wait([V_inst_1, V_inst_2, V_inst_3], spend_tx)

    assert isinstance(U_inst.contract, Unvaulting)
    assert isinstance(V_revault_inst.contract, Vault)
    assert manager.instances.index(U_inst) >= 0
    assert manager.instances.index(V_revault_inst) >= 0

    report.write(vault_description, format_tx_markdown(spend_tx, "Trigger (with revault) [3 vault inputs]"))

    spend_tx, _ = manager.get_spend_tx(
        (U_inst, "withdraw", {"withdrawal_pk": withdrawal_pk})
    )

    # TODO: get_spend_wit does not fill the transaction
    # according to the template (which the manager doesn't know)
    # Figure out a better way to let the framework handle this
    spend_tx.wit.vtxinwit = [manager.get_spend_wit(
        U_inst,
        "withdraw",
        {"withdrawal_pk": withdrawal_pk}
    )]

    spend_tx.nVersion = 2
    spend_tx.vin[0].nSequence = locktime

    mine_blocks(rpc, locktime - 1)

    manager.spend_and_wait(U_inst, spend_tx)
