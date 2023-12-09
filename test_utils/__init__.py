
from matt.btctools.auth_proxy import AuthServiceProxy


def mine_blocks(rpc: AuthServiceProxy, n_blocks: int) -> list[str]:
    address = rpc.getnewaddress()
    return rpc.generatetoaddress(n_blocks, address)
