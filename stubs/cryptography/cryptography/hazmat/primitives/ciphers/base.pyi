import abc
import typing
from cryptography import utils as utils
from cryptography.exceptions import AlreadyFinalized as AlreadyFinalized, AlreadyUpdated as AlreadyUpdated, NotYetFinalized as NotYetFinalized, UnsupportedAlgorithm as UnsupportedAlgorithm, _Reasons as _Reasons
from cryptography.hazmat.backends import _get_backend as _get_backend
from cryptography.hazmat.backends.interfaces import CipherBackend as CipherBackend
from cryptography.hazmat.primitives._cipheralgorithm import CipherAlgorithm as CipherAlgorithm
from cryptography.hazmat.primitives.ciphers import modes as modes
from typing import Any

class BlockCipherAlgorithm(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def block_size(self) -> int: ...

class CipherContext(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def update(self, data: bytes) -> bytes: ...
    @abc.abstractmethod
    def update_into(self, data: bytes, buf: Any) -> int: ...
    @abc.abstractmethod
    def finalize(self) -> bytes: ...

class AEADCipherContext(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def authenticate_additional_data(self, data: bytes) -> None: ...

class AEADDecryptionContext(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def finalize_with_tag(self, tag: bytes) -> bytes: ...

class AEADEncryptionContext(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def tag(self) -> bytes: ...

class Cipher:
    algorithm: Any = ...
    mode: Any = ...
    _backend: Any = ...
    def __init__(self, algorithm: CipherAlgorithm, mode: typing.Optional[modes.Mode], backend: Any=...) -> None: ...
    def encryptor(self): ...
    def decryptor(self): ...
    def _wrap_ctx(self, ctx: Any, encrypt: Any): ...

class _CipherContext:
    _ctx: Any = ...
    def __init__(self, ctx: Any) -> None: ...
    def update(self, data: bytes) -> bytes: ...
    def update_into(self, data: bytes, buf: Any) -> int: ...
    def finalize(self) -> bytes: ...

class _AEADCipherContext:
    _ctx: Any = ...
    _bytes_processed: int = ...
    _aad_bytes_processed: int = ...
    _tag: Any = ...
    _updated: bool = ...
    def __init__(self, ctx: Any) -> None: ...
    def _check_limit(self, data_size: int) -> Any: ...
    def update(self, data: bytes) -> bytes: ...
    def update_into(self, data: bytes, buf: Any) -> int: ...
    def finalize(self) -> bytes: ...
    def finalize_with_tag(self, tag: bytes) -> bytes: ...
    def authenticate_additional_data(self, data: bytes) -> None: ...

class _AEADEncryptionContext(_AEADCipherContext):
    @property
    def tag(self) -> bytes: ...
