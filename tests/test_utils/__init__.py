
from typing import List
from matt.btctools.auth_proxy import AuthServiceProxy


def mine_blocks(rpc: AuthServiceProxy, n_blocks: int) -> List[str]:
    address = rpc.getnewaddress()
    return rpc.generatetoaddress(n_blocks, address)
