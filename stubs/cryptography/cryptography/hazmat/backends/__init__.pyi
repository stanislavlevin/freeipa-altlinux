import typing
from typing import Any

_default_backend: typing.Any

def default_backend(): ...
def _get_backend(backend: Any): ...
