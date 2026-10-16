import asyncio
import struct
from tork.crypto import generate_ephemeral_keypair, derive_shared_key

async def send_frame(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(struct.pack("!I", len(data)) + data)
    await writer.drain()

async def receive_frame(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(4)
    length = struct.unpack("!I", header)[0]
    return await reader.readexactly(length)

async def perform_initiator_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float = 30.0) -> bytes:
    print("[i] Performing E2EE X25519 handshake (initiator)...")
    priv_key, pub_bytes = generate_ephemeral_keypair()
    
    # 1. Send our public key
    await send_frame(writer, pub_bytes)
    
    # 2. Receive peer's public key with timeout
    peer_pub_bytes = await asyncio.wait_for(receive_frame(reader), timeout=timeout)
    if len(peer_pub_bytes) != 32:
        raise ValueError("Invalid peer public key length received during handshake.")
    
    shared_key = derive_shared_key(priv_key, peer_pub_bytes)
    print("[i] Shared session key established.")
    return shared_key

async def perform_receiver_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float = 30.0) -> bytes:
    print("[i] Performing E2EE X25519 handshake (receiver)...")
    priv_key, pub_bytes = generate_ephemeral_keypair()
    
    # 1. Receive initiator's public key first to avoid deadlock
    peer_pub_bytes = await asyncio.wait_for(receive_frame(reader), timeout=timeout)
    if len(peer_pub_bytes) != 32:
        raise ValueError("Invalid peer public key length received during handshake.")
    
    # 2. Send our public key
    await send_frame(writer, pub_bytes)
    
    shared_key = derive_shared_key(priv_key, peer_pub_bytes)
    print("[i] Shared session key established.")
    return shared_key
