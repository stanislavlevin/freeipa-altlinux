from .wcwidth import wcswidth as wcswidth
from _pytest.compat import final as final
from typing import Any, Optional, Sequence, TextIO

def get_terminal_width() -> int: ...
def should_do_markup(file: TextIO) -> bool: ...

class TerminalWriter:
    _esctable: Any = ...
    _file: Any = ...
    hasmarkup: Any = ...
    _current_line: str = ...
    _terminal_width: Any = ...
    code_highlight: bool = ...
    def __init__(self, file: Optional[TextIO]=...) -> None: ...
    @property
    def fullwidth(self) -> int: ...
    @fullwidth.setter
    def fullwidth(self, value: int) -> None: ...
    @property
    def width_of_current_line(self) -> int: ...
    def markup(self, text: str, **markup: bool) -> str: ...
    def sep(self, sepchar: str, title: Optional[str]=..., fullwidth: Optional[int]=..., **markup: bool) -> None: ...
    def write(self, msg: str, *, flush: bool=..., **markup: bool) -> None: ...
    def line(self, s: str=..., **markup: bool) -> None: ...
    def flush(self) -> None: ...
    def _write_source(self, lines: Sequence[str], indents: Sequence[str]=...) -> None: ...
    def _highlight(self, source: str) -> str: ...
