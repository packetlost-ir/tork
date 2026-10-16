import asyncio
import argparse
import sys
import traceback
from tork.config import DEFAULT_LOCAL_PORT, SOCKS_PORT, normalize_and_validate_onion
from tork.network.tor import get_controller, create_onion_service, destroy_onion_service
from tork.network.server import PeerServer
from tork.network.client import connect_peer
from tork.network.protocol import send_frame, receive_frame, perform_initiator_handshake, perform_receiver_handshake
from tork.crypto import encrypt_message, decrypt_message

async def async_listen(local_port: int):
    print(f"Connecting to Tor daemon...")
    try:
        controller = get_controller()
    except Exception as e:
        print(f"Failed to connect to Tor control port: {e}", file=sys.stderr)
        return

    try:
        onion_hash, _, _ = create_onion_service(controller, local_port)
    except Exception as e:
        print(f"Failed to create ephemeral onion service: {e}", file=sys.stderr)
        controller.close()
        return

    full_onion = f"{onion_hash}.onion"
    print(f"Onion service created: {full_onion}")
    print(f"Listening on 127.0.0.1:{local_port}...")

    async def handle_connection(reader, writer):
        try:
            shared_key = await perform_receiver_handshake(reader, writer)
            print("[i] Receiving encrypted frame...")
            encrypted_payload = await receive_frame(reader)
            print("[i] Decrypting incoming payload...")
            plaintext_bytes = decrypt_message(shared_key, encrypted_payload)
            msg = plaintext_bytes.decode("utf-8", errors="replace")
            print(f"[Incoming - Decrypted E2EE] {msg}", flush=True)
        except Exception as e:
            print(f"[!] Error processing incoming message: {e}", file=sys.stderr, flush=True)
            traceback.print_exc()

    server = PeerServer("127.0.0.1", local_port, on_message_callback=handle_connection)
    await server.start()

    stop_event = asyncio.Event()

    try:
        while not stop_event.is_set():
            await asyncio.sleep(0.5)
    except asyncio.CancelledError:
        pass
    finally:
        print("\nShutting down server and removing onion service...")
        await server.stop()
        try:
            destroy_onion_service(controller, full_onion)
        except Exception as e:
            print(f"Error removing onion service: {e}", file=sys.stderr)
        try:
            controller.close()
        except Exception:
            pass
        print("Done.")

async def async_send(onion_address: str, message: str, socks_port: int):
    is_valid, normalized_addr, err_msg = normalize_and_validate_onion(onion_address)
    if not is_valid:
        print(f"Error: Invalid onion address '{onion_address}': {err_msg}", file=sys.stderr)
        sys.exit(1)

    print(f"Connecting to {normalized_addr} via Tor SOCKS5 (strict onion routing)...")
    try:
        reader, writer = await connect_peer(normalized_addr, socks_port=socks_port)
    except Exception as e:
        print(f"Error connecting to peer: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        shared_key = await perform_initiator_handshake(reader, writer)
        print("[i] Encrypting message with ChaCha20-Poly1305...")
        encrypted_payload = encrypt_message(shared_key, message.encode("utf-8"))
        print("[i] Sending encrypted frame...")
        await send_frame(writer, encrypted_payload)
        print("Message encrypted with ChaCha20-Poly1305 and delivered securely.")
    except Exception as e:
        print(f"Error sending message: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(description="Tork P2P Terminal Chat over Tor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    listen_parser = subparsers.add_parser("listen", help="Listen for incoming peer connections")
    listen_parser.add_argument("--local-port", type=int, default=DEFAULT_LOCAL_PORT, help="Local TCP port")

    send_parser = subparsers.add_parser("send", help="Send a message to a peer onion address")
    send_parser.add_argument("onion_address", type=str, help="Target peer onion address")
    send_parser.add_argument("message", type=str, help="Message text to send")
    send_parser.add_argument("--socks-port", type=int, default=SOCKS_PORT, help="Local SOCKS5 proxy port")

    args = parser.parse_args()

    if args.command == "listen":
        try:
            asyncio.run(async_listen(args.local_port))
        except KeyboardInterrupt:
            pass
    elif args.command == "send":
        try:
            asyncio.run(async_send(args.onion_address, args.message, args.socks_port))
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
