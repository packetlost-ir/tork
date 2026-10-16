import asyncio
import argparse
import sys
from tork.config import DEFAULT_LOCAL_PORT
from tork.network.tor import create_onion_service, destroy_onion_service
from tork.network.server import PeerServer

async def async_listen(local_port: int):
    print(f"Connecting to Tor daemon...")
    try:
        onion_hash, _, _ = create_onion_service(local_port)
    except Exception as e:
        print(f"Failed to create ephemeral onion service: {e}", file=sys.stderr)
        return

    full_onion = f"{onion_hash}.onion"
    print(f"Onion service created: {full_onion}")
    print(f"Listening on 127.0.0.1:{local_port}...")

    async def handle_msg(data, reader, writer):
        try:
            msg = data.decode("utf-8", errors="replace")
        except Exception:
            msg = repr(data)
        print(f"[Incoming] {msg}")

    server = PeerServer("127.0.0.1", local_port, on_message_callback=handle_msg)
    await server.start()

    stop_event = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (asyncio.CancelledError,):
        pass

    try:
        while not stop_event.is_set():
            await asyncio.sleep(0.5)
    except asyncio.CancelledError:
        pass
    finally:
        print("\nShutting down server and removing onion service...")
        await server.stop()
        try:
            destroy_onion_service(full_onion)
        except Exception as e:
            print(f"Error removing onion service: {e}", file=sys.stderr)
        print("Done.")

def main():
    parser = argparse.ArgumentParser(description="Tork P2P Terminal Chat over Tor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    listen_parser = subparsers.add_parser("listen", help="Listen for incoming peer connections")
    listen_parser.add_argument("--local-port", type=int, default=DEFAULT_LOCAL_PORT, help="Local TCP port")

    args = parser.parse_args()

    if args.command == "listen":
        try:
            asyncio.run(async_listen(args.local_port))
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
