import asyncio
from python_socks import ProxyType, ProxyError
from python_socks.async_.asyncio import Proxy
from tork.config import normalize_and_validate_onion, SOCKS_HOST, SOCKS_PORT, CONNECT_TIMEOUT

async def connect_peer(target_onion, socks_host=SOCKS_HOST, socks_port=SOCKS_PORT, timeout=CONNECT_TIMEOUT):
    is_valid, normalized_addr, err = normalize_and_validate_onion(target_onion)
    if not is_valid: raise ValueError(f"Invalid address: {err}")
    
    proxy = Proxy.create(proxy_type=ProxyType.SOCKS5, host=socks_host, port=socks_port, rdns=True)
    
    for attempt in range(6):
        try:
            sock = await asyncio.wait_for(proxy.connect(dest_host=normalized_addr, dest_port=80), timeout=30)
            return await asyncio.open_connection(sock=sock)
        except (ProxyError, OSError, asyncio.TimeoutError) as e:
            if attempt == 5: raise ConnectionError(f"Target unreachable: {e}")
            await asyncio.sleep(15)
