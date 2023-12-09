
from typing import Optional
from matt.btctools.auth_proxy import AuthServiceProxy
from . import ContractManager


class Environment:
    def __init__(self, rpc: AuthServiceProxy, manager: ContractManager, host: str, port: int, interactive: bool):
        self.rpc = rpc
        self.manager = manager
        self.host = host
        self.port = port
        self.interactive = interactive

    def prompt(self, message: Optional[str] = None):
        if message is not None:
            print(message)
        if self.interactive:
            print("Press Enter to continue...")
            input()
