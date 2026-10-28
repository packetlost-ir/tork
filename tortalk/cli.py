import asyncio
import argparse
import sys
import traceback
import pyperclip
from tork.config import DEFAULT_LOCAL_PORT, SOCKS_PORT, CONTROL_PORT, CONNECT_TIMEOUT, normalize_and_validate_onion, clean_hash
from tork.network.tor import get_controller, create_onion_service, destroy_onion_service
from tork.network.server import PeerServer
from tork.network.client import connect_peer
from tork.network.protocol import (
    send_frame, receive_frame, perform_protocol_handshake,
    encode_payload, decode_payload, OP_CHAT,
)
from tork.crypto import encrypt_message, decrypt_message
from tork.storage import StorageManager
from tork.ui.app import TorkApp

async def async_listen(local_port: int, control_port: int, timeout: float):
    print(f"Connecting to Tor daemon (control port {control_port})...")
    storage = StorageManager(config_dir=getattr(args_global, "config_dir", None), profile=getattr(args_global, "profile", None))
    identity = storage.load_identity()

    try:
        controller = get_controller(control_port=control_port)
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

    h = clean_hash(onion_hash)
    print(f"Onion service created (hash): {h}")
    print(f"Listening on 127.0.0.1:{local_port}...")

    display_name = getattr(args_global, "profile", None) or f"peer-{h[:6]}"

    async def handle_connection(reader, writer):
        try:
            shared_key, peer_hash, peer_name = await perform_protocol_handshake(
                reader, writer, h, display_name, False, timeout=timeout
            )
            print("[i] Receiving encrypted frame...")
            encrypted_payload = await receive_frame(reader)
            print("[i] Decrypting incoming payload...")
            plaintext_bytes = decrypt_message(shared_key, encrypted_payload)
            msg_type, name, sender_onion, msg = decode_payload(plaintext_bytes)
            
            # Nickname sync & Auto-save fallback
            sender_onion = sender_onion or peer_hash
            name = name or peer_name
            
            if sender_onion and sender_onion != h:
                alias = storage.find_alias_by_onion(sender_onion)
                if alias:
                    if name and alias != name:
                        if storage.update_alias(alias, name):
                            print(f"[i] Nickname synced: {alias} -> {name}", flush=True)
                else:
                    new_alias = name or f"peer-{sender_onion[:6]}"
                    storage.add_contact(new_alias, sender_onion)
                    print(f"[i] Discovered and saved contact: {new_alias} ({sender_onion[:8]}...)", flush=True)

            who = name or (clean_hash(sender_onion)[:8] if sender_onion else "Peer")
            print(f"[Incoming - Decrypted E2EE] [{who}] {msg}", flush=True)
        except Exception as e:
            print(f"[!] Error processing incoming message: {e}", file=sys.stderr, flush=True)
            traceback.print_exc()

    server = PeerServer("127.0.0.1", local_port, h, display_name, handle_connection)
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
            destroy_onion_service(controller, h)
        except Exception as e:
            print(f"Error removing onion service: {e}", file=sys.stderr)
        try:
            controller.close()
        except Exception:
            pass
        print("Done.")

async def async_send(target_arg: str, message: str, socks_port: int, timeout: float, config_dir=None, profile=None):
    storage = StorageManager(config_dir=config_dir, profile=profile)
    resolved_onion = storage.get_contact(target_arg) or target_arg

    is_valid, normalized_addr, err_msg = normalize_and_validate_onion(resolved_onion)
    if not is_valid:
        print(f"Error: Invalid onion address or unknown contact '{target_arg}': {err_msg}", file=sys.stderr)
        sys.exit(1)

    h = clean_hash(normalized_addr)
    print(f"Connecting to {h} via Tor SOCKS5 (port {socks_port})...")
    try:
        reader, writer = await connect_peer(normalized_addr, socks_port=socks_port, timeout=timeout)
    except Exception as e:
        print(f"Error connecting to peer: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        identity = storage.load_identity()
        self_hash = clean_hash(identity["service_id"]) if identity else ""
        display_name = profile or (f"peer-{self_hash[:6]}" if self_hash else "")

        shared_key, peer_hash, peer_name = await perform_protocol_handshake(
            reader, writer, self_hash, display_name, True, timeout=timeout
        )
        print("[i] Encrypting message with ChaCha20-Poly1305...")
        payload = encode_payload(display_name, self_hash, message)
        # Prepend OP_CHAT opcode for compatibility with PeerSession
        encrypted_payload = encrypt_message(shared_key, bytes([OP_CHAT]) + payload)
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

def handle_id(copy_to_clip: bool, control_port: int, config_dir=None, profile=None):
    storage = StorageManager(config_dir=config_dir, profile=profile)
    identity = storage.load_identity()
    if not identity:
        print("No identity found. Generating identity...")
        try:
            controller = get_controller(control_port=control_port)
            onion_hash, key_type, private_key = create_onion_service(controller, DEFAULT_LOCAL_PORT, await_publication=False)
            storage.save_identity(onion_hash, key_type, private_key)
            controller.close()
            identity = storage.load_identity()
        except Exception as e:
            print(f"Error generating identity via Tor daemon: {e}", file=sys.stderr)
            sys.exit(1)

    h = clean_hash(identity["service_id"])
    print(f"Your persistent Tor Onion Address (hash): {h}")
    if copy_to_clip:
        try:
            pyperclip.copy(h)
            print("Copied 56-character hash to clipboard.")
        except Exception as e:
            print(f"Could not copy to clipboard: {e}", file=sys.stderr)

def handle_contact(args):
    storage = StorageManager(config_dir=args.config_dir, profile=args.profile)
    subaction = args.contact_action

    if subaction == "add":
        success, res = storage.add_contact(args.alias, args.onion)
        if success:
            h = clean_hash(res)
            print(f"Contact '{args.alias}' added: {h}")
        else:
            print(f"Error adding contact: {res}", file=sys.stderr)
            sys.exit(1)
    elif subaction == "list":
        contacts = storage.list_contacts()
        if not contacts:
            print("No contacts saved.")
        else:
            print("Saved Contacts:")
            for alias, data in contacts.items():
                print(f"  {alias} -> {clean_hash(data['onion'])}")
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

args_global = None

def main():
    global args_global
    parser = argparse.ArgumentParser(description="Tork P2P Terminal Chat over Tor")
    
    # Global arguments
    parser.add_argument("--config-dir", type=str, default=None, help="Custom configuration directory")
    parser.add_argument("--profile", type=str, default=None, help="Profile name shorthand")
    parser.add_argument("-p", "--local-port", type=int, default=DEFAULT_LOCAL_PORT, help="Local TCP listen port")
    parser.add_argument("--socks-port", type=int, default=SOCKS_PORT, help="Tor SOCKS5 proxy port")
    parser.add_argument("--control-port", type=int, default=CONTROL_PORT, help="Tor ControlPort")
    parser.add_argument("--timeout", type=float, default=CONNECT_TIMEOUT, help="Connection / handshake timeout")

    subparsers = parser.add_subparsers(dest="command", required=False)

    listen_parser = subparsers.add_parser("listen", help="Listen for incoming peer connections")
    
    send_parser = subparsers.add_parser("send", help="Send a message to a peer onion address or contact alias")
    send_parser.add_argument("onion_address", type=str, help="Target peer onion address or contact alias")
    send_parser.add_argument("message", type=str, help="Message text to send")

    id_parser = subparsers.add_parser("id", help="Display local persistent 56-char onion hash")
    id_parser.add_argument("--copy", action="store_true", help="Copy hash to clipboard")

    chat_parser = subparsers.add_parser("chat", help="Launch Textual TUI chat interface")
    chat_parser.add_argument("target", nargs="?", default=None, help="Optional initial target contact or onion hash")

    contact_parser = subparsers.add_parser("contact", help="Manage saved contacts")
    contact_subparsers = contact_parser.add_subparsers(dest="contact_action", required=True)

    add_p = contact_subparsers.add_parser("add", help="Add a new contact")
    add_p.add_argument("alias", type=str, help="Contact alias")
    add_p.add_argument("onion", type=str, help="Peer onion address")

    contact_subparsers.add_parser("list", help="List all contacts")

    remove_p = contact_subparsers.add_parser("remove", help="Remove a contact")
    remove_p.add_argument("alias", type=str, help="Contact alias to remove")

    args, unknown = parser.parse_known_args()
    args_global = args

    command = args.command if args.command else "chat"
    target = getattr(args, "target", None)

    if command == "listen":
        try:
            asyncio.run(async_listen(args.local_port, args.control_port, args.timeout))
        except KeyboardInterrupt:
            pass
    elif command == "send":
        try:
            asyncio.run(async_send(args.onion_address, args.message, args.socks_port, args.timeout, config_dir=args.config_dir, profile=args.profile))
        except KeyboardInterrupt:
            pass
    elif command == "id":
        handle_id(args.copy, args.control_port, config_dir=args.config_dir, profile=args.profile)
    elif command == "contact":
        handle_contact(args)
    elif command == "chat":
        storage = StorageManager(config_dir=args.config_dir, profile=args.profile)
        resolved_target = None
        if target:
            resolved_target = storage.get_contact(target) or target
        app = TorkApp(
            initial_target=resolved_target,
            config_dir=args.config_dir,
            profile=args.profile,
            local_port=args.local_port,
            socks_port=args.socks_port,
            control_port=args.control_port,
            timeout=args.timeout
        )
        app.run()

if __name__ == "__main__":
    main()
