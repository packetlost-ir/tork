import asyncio
from tork.network.protocol import receive_frame, send_frame

class PeerServer:
    def __init__(self, host: str, port: int, on_message_callback=None):
        self.host = host
        self.port = port
        self.on_message_callback = on_message_callback
        self.server = None

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                data = await receive_frame(reader)
                if not data:
                    break
                if self.on_message_callback:
                    await self.on_message_callback(data, reader, writer)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        self.server = await asyncio.start_server(
            self._handle_connection, self.host, self.port
        )

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
