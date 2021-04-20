import typing
from cryptography.exceptions import UnsupportedAlgorithm as UnsupportedAlgorithm, _Reasons as _Reasons
from cryptography.hazmat.backends import _get_backend as _get_backend
from cryptography.hazmat.backends.interfaces import HMACBackend as HMACBackend
from cryptography.hazmat.primitives import constant_time as constant_time
from cryptography.hazmat.primitives.twofactor import InvalidToken as InvalidToken
from cryptography.hazmat.primitives.twofactor.hotp import HOTP as HOTP, _ALLOWED_HASH_TYPES as _ALLOWED_HASH_TYPES
from cryptography.hazmat.primitives.twofactor.utils import _generate_uri as _generate_uri
from typing import Any

class TOTP:
    _time_step: Any = ...
    _hotp: Any = ...
    def __init__(self, key: bytes, length: int, algorithm: _ALLOWED_HASH_TYPES, time_step: int, backend: Any=..., enforce_key_length: bool=...) -> None: ...
    def generate(self, time: typing.Union[int, float]) -> bytes: ...
    def verify(self, totp: bytes, time: int) -> None: ...
    def get_provisioning_uri(self, account_name: str, issuer: typing.Optional[str]) -> str: ...
