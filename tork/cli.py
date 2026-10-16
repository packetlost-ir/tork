import asyncio
import argparse
import sys
import traceback
import pyperclip
from tork.config import DEFAULT_LOCAL_PORT, SOCKS_PORT, normalize_and_validate_onion
from tork.network.tor import get_controller, create_onion_service, destroy_onion_service
from tork.network.server import PeerServer
from tork.network.client import connect_peer
from tork.network.protocol import send_frame, receive_frame, perform_initiator_handshake, perform_receiver_handshake
from tork.crypto import encrypt_message, decrypt_message
from tork.storage import StorageManager

async def async_listen(local_port: int):
    print(f"Connecting to Tor daemon...")
    storage = StorageManager()
    identity = storage.load_identity()

    try:
        controller = get_controller()
    except Exception as e:
        print(f"Failed to connect to Tor control port: {e}", file=sys.stderr)
        return

    try:
        if identity:
            print("Loading persistent identity...")
            onion_hash, _, _ = create_onion_service(
                controller,
                local_port,
                key_type=identity["key_type"],
                key_content=identity["private_key"]
            )
        else:
            print("Generating new persistent identity...")
            onion_hash, key_type, private_key = create_onion_service(controller, local_port)
            storage.save_identity(onion_hash, key_type, private_key)
    except Exception as e:
        print(f"Failed to configure ephemeral/persistent onion service: {e}", file=sys.stderr)
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

async def async_send(target_arg: str, message: str, socks_port: int):
    storage = StorageManager()
    # Check if target_arg is a contact alias first
    resolved_onion = storage.get_contact(target_arg)
    if not resolved_onion:
        resolved_onion = target_arg

    is_valid, normalized_addr, err_msg = normalize_and_validate_onion(resolved_onion)
    if not is_valid:
        print(f"Error: Invalid onion address or unknown contact '{target_arg}': {err_msg}", file=sys.stderr)
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

def handle_id(copy_to_clip: bool):
    storage = StorageManager()
    identity = storage.load_identity()
    if not identity:
        print("No identity found. Starting temporary listener or generating identity...")
        try:
            controller = get_controller()
            onion_hash, key_type, private_key = create_onion_service(controller, DEFAULT_LOCAL_PORT, await_publication=False)
            storage.save_identity(onion_hash, key_type, private_key)
            controller.close()
            identity = storage.load_identity()
        except Exception as e:
            print(f"Error generating identity via Tor daemon: {e}", file=sys.stderr)
            sys.exit(1)

    full_onion = f"{identity['service_id']}.onion"
    print(f"Your persistent Tor Onion Address: {full_onion}")
    if copy_to_clip:
        try:
            pyperclip.copy(full_onion)
            print("Copied onion address to clipboard.")
        except Exception as e:
            print(f"Could not copy to clipboard: {e}", file=sys.stderr)

def handle_contact(args):
    storage = StorageManager()
    subaction = args.contact_action

    if subaction == "add":
        success, res = storage.add_contact(args.alias, args.onion)
        if success:
            print(f"Contact '{args.alias}' added: {res}")
        else:
            print(f"Error adding contact: {res}", file=sys.stderr)
            sys.exit(1)
    elif subaction == "list":
        contacts = storage.list_contacts()
        if not contacts:
            print("No contacts saved.")
        else:
            print("Saved Contacts:")
            for alias, onion in contacts.items():
                print(f"  {alias} -> {onion}")
    elif subaction == "remove":
        removed = storage.remove_contact(args.alias)
        if removed:
            print(f"Contact '{args.alias}' removed.")
        else:
            print(f"Contact '{args.alias}' not found.", file=sys.stderr)
            sys.exit(1)
    else:
        print("Invalid contact action.", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Tork P2P Terminal Chat over Tor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    listen_parser = subparsers.add_parser("listen", help="Listen for incoming peer connections")
    listen_parser.add_argument("--local-port", type=int, default=DEFAULT_LOCAL_PORT, help="Local TCP port")

    send_parser = subparsers.add_parser("send", help="Send a message to a peer onion address or contact alias")
    send_parser.add_argument("onion_address", type=str, help="Target peer onion address or contact alias")
    send_parser.add_argument("message", type=str, help="Message text to send")
    send_parser.add_argument("--socks-port", type=int, default=SOCKS_PORT, help="Local SOCKS5 proxy port")

    id_parser = subparsers.add_parser("id", help="Display local persistent onion address")
    id_parser.add_argument("--copy", action="store_true", help="Copy onion address to clipboard")

    contact_parser = subparsers.add_parser("contact", help="Manage saved contacts")
    contact_subparsers = contact_parser.add_subparsers(dest="contact_action", required=True)

    add_p = contact_subparsers.add_parser("add", help="Add a new contact")
    add_p.add_argument("alias", type=str, help="Contact alias")
    add_p.add_argument("onion", type=str, help="Peer onion address")

    contact_subparsers.add_parser("list", help="List all contacts")

    remove_p = contact_subparsers.add_parser("remove", help="Remove a contact")
    remove_p.add_argument("alias", type=str, help="Contact alias to remove")

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
    elif args.command == "id":
        handle_id(args.copy)
    elif args.command == "contact":
        handle_contact(args)

if __name__ == "__main__":
    main()
