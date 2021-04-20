import abc
from cryptography.exceptions import UnsupportedAlgorithm as UnsupportedAlgorithm, _Reasons as _Reasons
from cryptography.hazmat.primitives import _serialization as _serialization
from typing import Any

_ED25519_KEY_SIZE: int
_ED25519_SIG_SIZE: int

class Ed25519PublicKey(metaclass=abc.ABCMeta):
    @classmethod
    def from_public_bytes(cls: Any, data: bytes) -> Ed25519PublicKey: ...
    @abc.abstractmethod
    def public_bytes(self, encoding: _serialization.Encoding, format: _serialization.PublicFormat) -> bytes: ...
    @abc.abstractmethod
    def verify(self, signature: bytes, data: bytes) -> None: ...

class Ed25519PrivateKey(metaclass=abc.ABCMeta):
    @classmethod
    def generate(cls: Any) -> Ed25519PrivateKey: ...
    @classmethod
    def from_private_bytes(cls: Any, data: bytes) -> Ed25519PrivateKey: ...
    @abc.abstractmethod
    def public_key(self) -> Ed25519PublicKey: ...
    @abc.abstractmethod
    def private_bytes(self, encoding: _serialization.Encoding, format: _serialization.PrivateFormat, encryption_algorithm: _serialization.KeySerializationEncryption) -> Any: ...
    @abc.abstractmethod
    def sign(self, data: bytes) -> bytes: ...
