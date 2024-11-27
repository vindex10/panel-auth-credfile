import dataclasses
import json

import bcrypt

from panel_auth_credfile.config import CFG


@dataclasses.dataclass
class User:
    username: str
    password_hash: bytes
    metadata: dict[str, str]


def hash_password(password: str):
    """Generates a hashed version of the provided password."""
    pw = bytes(password, "utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pw, salt)


def cmp_password(password: str, password_hash: bytes):
    return bcrypt.checkpw(password.encode("utf-8"), password_hash)


_CREDS_FILE = None


def CREDS_FILE():
    global _CREDS_FILE
    if _CREDS_FILE is None:
        _CREDS_FILE = read_credentials_file(CFG()["credentials_file"])
    return _CREDS_FILE


def read_credentials_file(creds_path):
    with open(creds_path, "r", encoding="utf-8") as fin:
        data = json.load(fin)
    res = {}
    for user in data:
        res[user["username"]] = User(
            username=user["username"],
            password_hash=user["password_hash"].encode("utf-8"),
            metadata=user["metadata"],
        )
    return res
