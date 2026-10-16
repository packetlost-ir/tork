import os
import json
from pathlib import Path
from tork.config import normalize_and_validate_onion

class StorageManager:
    def __init__(self):
        self.config_dir = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "tork"
        self.config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.identity_file = self.config_dir / "identity.json"
        self.contacts_file = self.config_dir / "contacts.json"

    def load_identity(self) -> dict | None:
        if self.identity_file.exists():
            try:
                with open(self.identity_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    def save_identity(self, service_id: str, key_type: str, private_key: str) -> None:
        data = {
            "service_id": service_id,
            "key_type": key_type,
            "private_key": private_key
        }
        with open(self.identity_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.chmod(self.identity_file, 0o600)

    def _load_contacts_raw(self) -> dict:
        if self.contacts_file.exists():
            try:
                with open(self.contacts_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_contacts_raw(self, contacts: dict) -> None:
        with open(self.contacts_file, "w", encoding="utf-8") as f:
            json.dump(contacts, f, indent=2)
        os.chmod(self.contacts_file, 0o600)

    def add_contact(self, alias: str, onion: str) -> tuple[bool, str]:
        is_valid, normalized, err = normalize_and_validate_onion(onion)
        if not is_valid:
            return False, f"Invalid onion address: {err}"
        
        contacts = self._load_contacts_raw()
        contacts[alias] = normalized
        self._save_contacts_raw(contacts)
        return True, normalized

    def get_contact(self, alias: str) -> str | None:
        contacts = self._load_contacts_raw()
        return contacts.get(alias)

    def list_contacts(self) -> dict[str, str]:
        return self._load_contacts_raw()

    def remove_contact(self, alias: str) -> bool:
        contacts = self._load_contacts_raw()
        if alias in contacts:
            del contacts[alias]
            self._save_contacts_raw(contacts)
            return True
        return False
