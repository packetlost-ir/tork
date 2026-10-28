import asyncio
import struct
import json
import time
from tortalk.crypto import generate_ephemeral_keypair, derive_shared_key, encrypt_message, decrypt_message

# Opcodes
OP_HANDSHAKE_INIT = 1
OP_HANDSHAKE_ACK = 2
OP_CHAT = 3
OP_PING = 4
OP_PONG = 5

async def send_frame(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(struct.pack("!I", len(data)) + data)
    await writer.drain()

async def receive_frame(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(4)
    length = struct.unpack("!I", header)[0]
    return await reader.readexactly(length)

class PeerSession:
    def __init__(self, reader, writer, shared_key, peer_hash, peer_name, is_initiator, app_callback):
        self.reader = reader
        self.writer = writer
        self.shared_key = shared_key
        self.peer_hash = peer_hash
        self.peer_name = peer_name
        self.is_initiator = is_initiator
        self.app_callback = app_callback
        self.last_seen = time.time()
        self.active = True
        self._read_task = None
        self._keepalive_task = None

    def start(self):
        self._read_task = asyncio.create_task(self._reader_loop())
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())

    async def send_op(self, opcode: int, payload_dict: dict = None):
        if not self.active: return
        data = json.dumps(payload_dict or {}).encode("utf-8")
        encrypted = encrypt_message(self.shared_key, bytes([opcode]) + data)
        try:
            await send_frame(self.writer, encrypted)
        except Exception:
            await self.close()

    async def _reader_loop(self):
        try:
            while self.active:
                encrypted = await receive_frame(self.reader)
                decrypted = decrypt_message(self.shared_key, encrypted)
                opcode = decrypted[0]
                payload = json.loads(decrypted[1:].decode("utf-8"))
                self.last_seen = time.time()

                if opcode == OP_CHAT:
                    await self.app_callback("chat", self.peer_hash, payload)
                elif opcode == OP_PING:
                    await self.send_op(OP_PONG)
                elif opcode == OP_PONG:
                    pass
        except Exception:
            pass
        finally:
            await self.close()

    async def _keepalive_loop(self):
        try:
            while self.active:
                await asyncio.sleep(20)
                if time.time() - self.last_seen > 60:
                    break
                await self.send_op(OP_PING)
        except Exception:
            pass
        finally:
            await self.close()

    async def close(self):
        if not self.active: return
        self.active = False
        if self._read_task: self._read_task.cancel()
        if self._keepalive_task: self._keepalive_task.cancel()
        try:
            self.writer.close()
            # Non-blocking wait_closed to avoid hang on exit
            await asyncio.wait_for(self.writer.wait_closed(), timeout=0.5)
        except Exception: pass
        await self.app_callback("closed", self.peer_hash, None)

async def perform_protocol_handshake(reader, writer, local_hash, local_name, is_initiator, timeout=30):
    priv_key, pub_bytes = generate_ephemeral_keypair()
    if is_initiator:
        await send_frame(writer, pub_bytes)
        peer_pub = await asyncio.wait_for(receive_frame(reader), timeout)
    else:
        peer_pub = await asyncio.wait_for(receive_frame(reader), timeout)
        await send_frame(writer, pub_bytes)
    
    shared_key = derive_shared_key(priv_key, peer_pub)
    
    # Secure Identity Exchange
    if is_initiator:
        init_data = json.dumps({"o": local_hash, "n": local_name}).encode("utf-8")
        await send_frame(writer, encrypt_message(shared_key, bytes([OP_HANDSHAKE_INIT]) + init_data))
        resp = decrypt_message(shared_key, await asyncio.wait_for(receive_frame(reader), timeout))
        if resp[0] != OP_HANDSHAKE_ACK: raise ValueError("Invalid ack")
        peer_info = json.loads(resp[1:].decode("utf-8"))
    else:
        req = decrypt_message(shared_key, await asyncio.wait_for(receive_frame(reader), timeout))
        if req[0] != OP_HANDSHAKE_INIT: raise ValueError("Invalid init")
        peer_info = json.loads(req[1:].decode("utf-8"))
        ack_data = json.dumps({"o": local_hash, "n": local_name}).encode("utf-8")
        await send_frame(writer, encrypt_message(shared_key, bytes([OP_HANDSHAKE_ACK]) + ack_data))
        
    return shared_key, peer_info["o"], peer_info["n"]

def encode_payload(display_name: str, sender_onion: str, message: str, msg_type: str = "chat") -> bytes:
    envelope = {
        "t": msg_type,
        "n": display_name or "",
        "o": (sender_onion or "").removesuffix(".onion"),
        "m": message,
    }
    # For cli compatibility with opcode-based protocol, we prepend OP_CHAT if it's a chat message
    # But wait, cli listen/send currently don't use PeerSession.
    # To keep it simple, let's make decode_payload handle both raw envelope and opcode+envelope.
    return json.dumps(envelope, ensure_ascii=False).encode("utf-8")

def decode_payload(data: bytes) -> tuple[str, str, str, str]:
    # Returns (type, display_name, sender_onion_hash, message).
    # Handle optional opcode prefix (1 byte)
    offset = 0
    if len(data) > 0 and data[0] in (OP_HANDSHAKE_INIT, OP_HANDSHAKE_ACK, OP_CHAT, OP_PING, OP_PONG):
        offset = 1
    
    try:
        obj = json.loads(data[offset:].decode("utf-8"))
        if isinstance(obj, dict):
            # If it's a PeerSession style chat packet {"m": ..., "ts": ...}
            if "m" in obj and "t" not in obj:
                return "chat", "", "", obj.get("m", "")
            return str(obj.get("t", "chat")), str(obj.get("n", "")), str(obj.get("o", "")), str(obj.get("m", ""))
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    return "chat", "", "", data.decode("utf-8", errors="replace")
