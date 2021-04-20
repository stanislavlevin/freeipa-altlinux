import typing
from cryptography.exceptions import UnsupportedAlgorithm as UnsupportedAlgorithm, _Reasons as _Reasons
from cryptography.hazmat.backends import _get_backend as _get_backend
from cryptography.hazmat.backends.interfaces import HMACBackend as HMACBackend
from cryptography.hazmat.primitives import constant_time as constant_time, hmac as hmac
from cryptography.hazmat.primitives.hashes import SHA1 as SHA1, SHA256 as SHA256, SHA512 as SHA512
from cryptography.hazmat.primitives.twofactor import InvalidToken as InvalidToken
from cryptography.hazmat.primitives.twofactor.utils import _generate_uri as _generate_uri
from typing import Any

_ALLOWED_HASH_TYPES: Any

class HOTP:
    _key: Any = ...
    _length: Any = ...
    _algorithm: Any = ...
    _backend: Any = ...
    def __init__(self, key: bytes, length: int, algorithm: _ALLOWED_HASH_TYPES, backend: Any=..., enforce_key_length: bool=...) -> None: ...
    def generate(self, counter: int) -> bytes: ...
    def verify(self, hotp: bytes, counter: int) -> None: ...
    def _dynamic_truncate(self, counter: int) -> int: ...
    def get_provisioning_uri(self, account_name: str, counter: int, issuer: typing.Optional[str]) -> str: ...
