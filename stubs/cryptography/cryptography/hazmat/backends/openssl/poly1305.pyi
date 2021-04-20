from cryptography.exceptions import InvalidSignature as InvalidSignature
from cryptography.hazmat.primitives import constant_time as constant_time
from typing import Any

_POLY1305_TAG_SIZE: int
_POLY1305_KEY_SIZE: int

class _Poly1305Context:
    _backend: Any = ...
    _evp_pkey: Any = ...
    _ctx: Any = ...
    def __init__(self, backend: Any, key: Any) -> None: ...
    def update(self, data: Any) -> None: ...
    def finalize(self): ...
    def verify(self, tag: Any) -> None: ...
