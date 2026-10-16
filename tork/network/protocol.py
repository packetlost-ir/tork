import asyncio
import struct

async def send_frame(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(struct.pack("!I", len(data)) + data)
    await writer.drain()

async def receive_frame(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(4)
    length = struct.unpack("!I", header)[0]
    return await reader.readexactly(length)
