import pytest

import sys
import os
from pathlib import Path

from matt.btctools.auth_proxy import AuthServiceProxy
from matt.manager import ContractManager
from test_utils.utxograph import create_utxo_graph

root_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../')
sys.path.append(root_path)


rpc_url = "http://%s:%s@%s:%s" % (
    os.getenv("BTC_RPC_USER", "rpcuser"),
    os.getenv("BTC_RPC_PASSWORD", "rpcpass"),
    os.getenv("BTC_RPC_HOST", "localhost"),
    os.getenv("BTC_RPC_PORT", "18443")
)


def pytest_addoption(parser):
    parser.addoption("--utxo_graph", action="store_true")


@pytest.fixture
def utxo_graph(request: pytest.FixtureRequest):
    return request.config.getoption("--utxo_graph", False)


@pytest.fixture(scope="session")
def rpc():
    return AuthServiceProxy(f"{rpc_url}/wallet/testwallet")


@pytest.fixture
def manager(rpc, request: pytest.FixtureRequest, utxo_graph: bool):
    manager = ContractManager(rpc, mine_automatically=True, poll_interval=0.01)
    yield manager

    if utxo_graph:
        # Create the "tests/graphs" directory if it doesn't exist
        path = Path("tests/graphs")
        path.mkdir(exist_ok=True)
        create_utxo_graph(manager, f"tests/graphs/{request.node.name}.html")


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
