import asyncio
import traceback
from python_socks import ProxyType, ProxyError
from python_socks.async_.asyncio import Proxy
from tork.config import normalize_and_validate_onion, SOCKS_HOST, SOCKS_PORT

async def _open_onion_stream(target_onion: str, socks_host: str, socks_port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    dest_host = target_onion if target_onion.endswith(".onion") else f"{target_onion}.onion"

    proxy = Proxy.create(
        proxy_type=ProxyType.SOCKS5,
        host=socks_host,
        port=socks_port,
        rdns=True
    )

    sock = await proxy.connect(dest_host=dest_host, dest_port=80)
    reader, writer = await asyncio.open_connection(sock=sock)
    return reader, writer

async def connect_peer(
    target_onion: str,
    socks_host: str = SOCKS_HOST,
    socks_port: int = SOCKS_PORT,
    timeout: float = 120.0,
    max_retries: int = 6,
    retry_delay: float = 15.0
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    is_valid, normalized_addr, err_msg = normalize_and_validate_onion(target_onion)
    if not is_valid:
        raise ValueError(f"Invalid onion address '{target_onion}': {err_msg}")

    start_time = asyncio.get_running_loop().time()
    attempt = 1

    while True:
        try:
            elapsed = asyncio.get_running_loop().time() - start_time
            remaining = max(5.0, timeout - elapsed)

            reader, writer = await asyncio.wait_for(
                _open_onion_stream(normalized_addr, socks_host, socks_port),
                timeout=remaining
            )
            return reader, writer
        except (ValueError, TypeError, AttributeError) as err:
            raise
        except (ProxyError, OSError, asyncio.TimeoutError) as net_err:
            elapsed = asyncio.get_running_loop().time() - start_time
            if attempt >= max_retries or elapsed >= timeout:
                raise TimeoutError(
                    f"Target onion service unreachable via Tor after {attempt} attempts ({elapsed:.1f}s elapsed): {net_err}"
                )
            
            print(f"[i] Waiting for Onion service descriptor to propagate across Tor network (attempt {attempt}/{max_retries}, retrying in {int(retry_delay)}s)...")
            await asyncio.sleep(retry_delay)
            attempt += 1
        except Exception as unknown_err:
            elapsed = asyncio.get_running_loop().time() - start_time
            if attempt >= max_retries or elapsed >= timeout:
                raise ConnectionError(
                    f"Failed to connect to {normalized_addr} via Tor SOCKS5 after {attempt} attempts: {unknown_err}"
                )
            print(f"[i] Connection attempt {attempt}/{max_retries} failed ({unknown_err}), retrying in {int(retry_delay)}s...")
            await asyncio.sleep(retry_delay)
            attempt += 1
