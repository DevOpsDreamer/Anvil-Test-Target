"""
Data serialization/deserialization utilities.
VULNERABLE: Multiple deserialization issues (CWE-502)
"""
import pickle
import yaml
import marshal
import base64
from flask import request


def deserialize_session(session_data: str) -> dict:
    """
    Deserialize a user session from base64-encoded pickle.
    VULNERABLE: CWE-502 — pickle.loads on attacker-controlled data
    Exploit: send crafted pickle payload that executes os.system()
    """
    raw = base64.b64decode(session_data)
    # VULNERABLE: pickle.loads with no validation
    return pickle.loads(raw)


def load_config(config_yaml: str) -> dict:
    """
    Load application config from YAML string.
    VULNERABLE: CWE-502 — yaml.load without safe Loader
    Exploit: !!python/object/apply:os.system ["cat flag.txt"]
    """
    # VULNERABLE: yaml.load without Loader=yaml.SafeLoader
    return yaml.load(config_yaml)


def restore_object(data: bytes) -> object:
    """
    Restore a Python object from marshal format.
    VULNERABLE: CWE-502 — marshal.loads on untrusted data
    """
    # VULNERABLE: marshal.loads
    return marshal.loads(data)


def load_user_preferences(raw_data: str) -> dict:
    """
    Load preferences sent by client.
    VULNERABLE: CWE-502 — deserializes request data directly
    """
    decoded = base64.b64decode(request.data)
    # VULNERABLE: pickle.loads on request body
    prefs = pickle.loads(decoded)
    return prefs
