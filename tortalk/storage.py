import os
import json
from pathlib import Path
from tortalk.config import normalize_and_validate_onion, resolve_config_dir

class StorageManager:
    def __init__(self, config_dir: str | Path | None = None, profile: str | None = None):
        self.config_dir = resolve_config_dir(config_dir, profile)
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
        if not self.contacts_file.exists():
            return {}
        try:
            with open(self.contacts_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    # Flatten list of objects to dict indexed by alias/nickname
                    return {item.get("nickname") or item.get("alias") or f"peer-{str(item.get('onion'))[:6]}": item for item in data if isinstance(item, dict)}
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_contacts_raw(self, contacts: dict) -> None:
        with open(self.contacts_file, "w", encoding="utf-8") as f:
            json.dump(contacts, f, indent=2)
        os.chmod(self.contacts_file, 0o600)

    def list_contacts(self) -> dict[str, dict]:
        """Returns normalized contacts: { alias: { nickname, onion, last_seen } }"""
        raw = self._load_contacts_raw()
        normalized = {}
        for key, val in raw.items():
            if isinstance(val, str):
                normalized[key] = {"nickname": key, "onion": val, "last_seen": None}
            elif isinstance(val, list):
                # Handle nested list quirk mentioned in issue
                onion_str = val[0].get("onion", "") if val and isinstance(val[0], dict) else ""
                normalized[key] = {"nickname": key, "onion": onion_str, "last_seen": None}
            elif isinstance(val, dict):
                normalized[key] = {
                    "nickname": val.get("nickname") or val.get("alias") or key,
                    "onion": val.get("onion", ""),
                    "last_seen": val.get("last_seen")
                }
        return normalized

    def add_contact(self, alias: str, onion: str) -> tuple[bool, str]:
        is_valid, normalized_onion, err = normalize_and_validate_onion(onion)
        if not is_valid:
            return False, f"Invalid onion address: {err}"
        
        target_hash = normalized_onion.removesuffix(".onion")
        contacts = self._load_contacts_raw()
        
        # Deduplicate by onion hash
        existing_alias = self.find_alias_by_onion(target_hash)
        if existing_alias:
            if existing_alias != alias:
                # Rename the contact key to the new alias
                data = contacts.pop(existing_alias)
                if isinstance(data, dict):
                    data["nickname"] = alias
                else:
                    data = {"nickname": alias, "onion": target_hash}
                contacts[alias] = data
            else:
                if isinstance(contacts[alias], dict):
                    contacts[alias]["nickname"] = alias
            self._save_contacts_raw(contacts)
            return True, target_hash

        contacts[alias] = {
            "nickname": alias,
            "onion": target_hash,
            "last_seen": None
        }
        self._save_contacts_raw(contacts)
        return True, target_hash

    def get_contact(self, alias: str) -> str | None:
        """Returns clean 56-char onion string for an alias."""
        contacts = self.list_contacts()
        data = contacts.get(alias)
        if data:
            return data.get("onion")
        return None

    def find_alias_by_onion(self, onion: str) -> str | None:
        target = onion.removesuffix(".onion")
        for alias, data in self.list_contacts().items():
            if data.get("onion") == target:
                return alias
        return None

    def update_alias(self, old_alias: str, new_alias: str) -> bool:
        new_alias = (new_alias or "").strip()
        if not new_alias or new_alias == old_alias:
            return False
        
        contacts = self._load_contacts_raw()
        if old_alias not in contacts or new_alias in contacts:
            return False
        
        data = contacts.pop(old_alias)
        if isinstance(data, dict):
            data["nickname"] = new_alias
        contacts[new_alias] = data
        self._save_contacts_raw(contacts)
        return True
