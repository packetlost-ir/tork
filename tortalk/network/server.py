import asyncio
import traceback
from tortalk.network.protocol import perform_protocol_handshake

class PeerServer:
    def __init__(self, host, port, local_hash, local_name, session_callback):
        self.host = host
        self.port = port
        self.local_hash = local_hash
        self.local_name = local_name
        self.session_callback = session_callback
        self.server = None

    async def _handle_connection(self, reader, writer):
        try:
            shared_key, peer_hash, peer_name = await perform_protocol_handshake(
                reader, writer, self.local_hash, self.local_name, False
            )
            await self.session_callback(reader, writer, shared_key, peer_hash, peer_name, False)
        except Exception as e:
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass

    async def start(self):
        self.server = await asyncio.start_server(self._handle_connection, self.host, self.port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
