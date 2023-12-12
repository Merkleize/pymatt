import pytest

import os

from matt.btctools.auth_proxy import AuthServiceProxy
from matt.manager import ContractManager


rpc_url = "http://%s:%s@%s:%s" % (
    os.getenv("BTC_RPC_USER", "rpcuser"),
    os.getenv("BTC_RPC_PASSWORD", "rpcpass"),
    os.getenv("BTC_RPC_HOST", "localhost"),
    os.getenv("BTC_RPC_PORT", "18443")
)


@pytest.fixture(scope="session")
def rpc():
    return AuthServiceProxy(rpc_url)


@pytest.fixture(scope="session")
def rpc_test_wallet():
    return AuthServiceProxy(f"{rpc_url}/wallet/test_wallet")


@pytest.fixture
def manager(rpc):
    return ContractManager([], rpc, mine_automatically=True, poll_interval=0.01)

@pytest.fixture(scope="session")
def report_file():
    with open("report.md", "w") as file:
        yield file