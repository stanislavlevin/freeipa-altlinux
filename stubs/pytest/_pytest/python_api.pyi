import _pytest._code
from _pytest.compat import STRING_TYPES as STRING_TYPES, final as final
from _pytest.outcomes import fail as fail
from decimal import Decimal
from numpy import ndarray as ndarray
from types import TracebackType
from typing import Any, Optional, Pattern, Tuple, Type, TypeVar, Union

def _non_numeric_type_error(value: Any, at: Optional[str]) -> TypeError: ...

class ApproxBase:
    __array_ufunc__: Any = ...
    __array_priority__: int = ...
    expected: Any = ...
    abs: Any = ...
    rel: Any = ...
    nan_ok: Any = ...
    def __init__(self, expected: Any, rel: Any=..., abs: Any=..., nan_ok: bool=...) -> None: ...
    def __repr__(self) -> str: ...
    def __eq__(self, actual: Any) -> bool: ...
    __hash__: Any = ...
    def __ne__(self, actual: Any) -> bool: ...
    def _approx_scalar(self, x: Any) -> ApproxScalar: ...
    def _yield_comparisons(self, actual: Any) -> None: ...
    def _check_type(self) -> None: ...

def _recursive_list_map(f: Any, x: Any): ...

class ApproxNumpy(ApproxBase):
    def __repr__(self) -> str: ...
    def __eq__(self, actual: Any) -> bool: ...
    def _yield_comparisons(self, actual: Any) -> None: ...

class ApproxMapping(ApproxBase):
    def __repr__(self) -> str: ...
    def __eq__(self, actual: Any) -> bool: ...
    def _yield_comparisons(self, actual: Any) -> None: ...
    def _check_type(self) -> None: ...

class ApproxSequencelike(ApproxBase):
    def __repr__(self) -> str: ...
    def __eq__(self, actual: Any) -> bool: ...
    def _yield_comparisons(self, actual: Any): ...
    def _check_type(self) -> None: ...

class ApproxScalar(ApproxBase):
    DEFAULT_ABSOLUTE_TOLERANCE: Union[float, Decimal] = ...
    DEFAULT_RELATIVE_TOLERANCE: Union[float, Decimal] = ...
    def __repr__(self) -> str: ...
    def __eq__(self, actual: Any) -> bool: ...
    __hash__: Any = ...
    @property
    def tolerance(self): ...

class ApproxDecimal(ApproxScalar):
    DEFAULT_ABSOLUTE_TOLERANCE: Any = ...
    DEFAULT_RELATIVE_TOLERANCE: Any = ...

def approx(expected: Any, rel: Any=..., abs: Any=..., nan_ok: bool=...) -> ApproxBase: ...
def _is_numpy_array(obj: object) -> bool: ...
def _as_numpy_array(obj: object) -> Optional[ndarray]: ...
_E = TypeVar('_E', bound=BaseException)

def raises(expected_exception: Union[Type[_E], Tuple[Type[_E], ...]], *, match: Optional[Union[str, Pattern[str]]]=...) -> RaisesContext[_E]: ...

class RaisesContext:
    expected_exception: Any = ...
    message: Any = ...
    match_expr: Any = ...
    excinfo: Any = ...
    def __init__(self, expected_exception: Union[Type[_E], Tuple[Type[_E], ...]], message: str, match_expr: Optional[Union[str, Pattern[str]]]=...) -> None: ...
    def __enter__(self) -> _pytest._code.ExceptionInfo[_E]: ...
    def __exit__(self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]) -> bool: ...
