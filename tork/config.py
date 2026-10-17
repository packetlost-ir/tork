import re
from pathlib import Path

SOCKS_HOST: str = "127.0.0.1"
SOCKS_PORT: int = 9050
CONTROL_PORT: int = 9051
DEFAULT_LOCAL_PORT: int = 5666
CONNECT_TIMEOUT: float = 120.0

ONION_REGEX = re.compile(r"^[a-z2-7]{56}\.onion$")

def normalize_and_validate_onion(raw_input: str) -> tuple[bool, str, str]:
    if not isinstance(raw_input, str):
        return False, "", "Input must be a string."
    
    val = raw_input.strip().lower()
    for proto in ("http://", "https://", "socks5://", "socks://"):
        if val.startswith(proto):
            val = val[len(proto):]
            break
            
    val = val.split("/")[0]
    
    if len(val) == 56 and re.match(r"^[a-z2-7]{56}$", val):
        val = f"{val}.onion"
        
    if ONION_REGEX.match(val):
        return True, val, ""
        
    return False, raw_input, "Invalid .onion address format."

def clean_hash(onion: object) -> str:
    if not onion:
        return ""
    
    # Handle schema variance (list of dicts, flat dicts, or strings)
    if isinstance(onion, dict):
        onion = onion.get("onion", "")
    elif isinstance(onion, list) and len(onion) > 0:
        first = onion[0]
        onion = first.get("onion", "") if isinstance(first, dict) else str(first)
    elif not isinstance(onion, str):
        onion = str(onion)
    
    val = onion.strip().lower()
    for proto in ("http://", "https://", "socks5://", "socks://"):
        if val.startswith(proto):
            val = val[len(proto):]
            break
    val = val.split("/")[0]
    if val.endswith(".onion"):
        val = val[:-6]
    return val

def resolve_config_dir(config_dir: str | Path | None = None, profile: str | None = None) -> Path:
    if config_dir:
        return Path(config_dir).expanduser().resolve()
    if profile:
        return (Path.home() / ".config" / "tork" / "profiles" / profile).resolve()
    return (Path.home() / ".config" / "tork").resolve()
