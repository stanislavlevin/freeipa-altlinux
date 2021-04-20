from cryptography import utils as utils
from typing import Any

class ObjectIdentifier:
    _dotted_string: Any = ...
    def __init__(self, dotted_string: str) -> None: ...
    def __eq__(self, other: Any) -> Any: ...
    def __ne__(self, other: Any) -> Any: ...
    def __repr__(self): ...
    def __hash__(self) -> Any: ...
    @property
    def _name(self): ...
    dotted_string: Any = ...
