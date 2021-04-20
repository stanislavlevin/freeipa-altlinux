import warnings
from _pytest.compat import final as final
from _pytest.deprecated import check_ispytest as check_ispytest
from _pytest.fixtures import fixture as fixture
from _pytest.outcomes import fail as fail
from types import TracebackType
from typing import Any, Generator, Iterator, List, Optional, Pattern, Tuple, Type, TypeVar, Union

T = TypeVar('T')

def recwarn() -> Generator[WarningsRecorder, None, None]: ...
def deprecated_call(*, match: Optional[Union[str, Pattern[str]]]=...) -> WarningsRecorder: ...
def warns(expected_warning: Optional[Union[Type[Warning], Tuple[Type[Warning], ...]]], *, match: Optional[Union[str, Pattern[str]]]=...) -> WarningsChecker: ...

class WarningsRecorder(warnings.catch_warnings):
    _entered: bool = ...
    _list: Any = ...
    def __init__(self, *, _ispytest: bool=...) -> None: ...
    @property
    def list(self) -> List[warnings.WarningMessage]: ...
    def __getitem__(self, i: int) -> warnings.WarningMessage: ...
    def __iter__(self) -> Iterator[warnings.WarningMessage]: ...
    def __len__(self) -> int: ...
    def pop(self, cls: Type[Warning]=...) -> warnings.WarningMessage: ...
    def clear(self) -> None: ...
    def __enter__(self) -> WarningsRecorder: ...
    def __exit__(self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]) -> None: ...

class WarningsChecker(WarningsRecorder):
    expected_warning: Any = ...
    match_expr: Any = ...
    def __init__(self, expected_warning: Optional[Union[Type[Warning], Tuple[Type[Warning], ...]]]=..., match_expr: Optional[Union[str, Pattern[str]]]=..., *, _ispytest: bool=...) -> None: ...
    def __exit__(self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]) -> None: ...
