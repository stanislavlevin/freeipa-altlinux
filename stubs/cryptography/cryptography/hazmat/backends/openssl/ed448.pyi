from cryptography import exceptions as exceptions
from cryptography.hazmat.primitives import serialization as serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey as Ed448PrivateKey, Ed448PublicKey as Ed448PublicKey
from typing import Any

_ED448_KEY_SIZE: int
_ED448_SIG_SIZE: int

class _Ed448PublicKey(Ed448PublicKey):
    _backend: Any = ...
    _evp_pkey: Any = ...
    def __init__(self, backend: Any, evp_pkey: Any) -> None: ...
    def public_bytes(self, encoding: serialization.Encoding, format: serialization.PublicFormat) -> bytes: ...
    def _raw_public_bytes(self) -> bytes: ...
    def verify(self, signature: bytes, data: bytes) -> None: ...

class _Ed448PrivateKey(Ed448PrivateKey):
    _backend: Any = ...
    _evp_pkey: Any = ...
    def __init__(self, backend: Any, evp_pkey: Any) -> None: ...
    def public_key(self) -> Ed448PublicKey: ...
    def sign(self, data: bytes) -> bytes: ...
    def private_bytes(self, encoding: serialization.Encoding, format: serialization.PrivateFormat, encryption_algorithm: serialization.KeySerializationEncryption) -> bytes: ...
    def _raw_private_bytes(self) -> bytes: ...
