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
    return ContractManager(rpc, mine_automatically=True, poll_interval=0.01)


class TestReport:
    def __init__(self):
        self.sections = {}

    def write(self, section_name, content):
        if section_name not in self.sections:
            self.sections[section_name] = []
        self.sections[section_name].append(content)

    def finalize_report(self, filename):
        with open(filename, "w") as file:
            for section, contents in self.sections.items():
                file.write(f"## {section}\n")
                for content in contents:
                    file.write(content + "\n")
                file.write("\n")


@pytest.fixture(scope="session")
def report():
    report_obj = TestReport()
    yield report_obj
    report_obj.finalize_report("report.md")
