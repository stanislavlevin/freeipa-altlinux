import logging
from _pytest import nodes as nodes
from _pytest._io import TerminalWriter as TerminalWriter
from _pytest.capture import CaptureManager as CaptureManager
from _pytest.compat import final as final, nullcontext as nullcontext
from _pytest.config import Config as Config, UsageError as UsageError, _strtobool as _strtobool, create_terminal_writer as create_terminal_writer, hookimpl as hookimpl
from _pytest.config.argparsing import Parser as Parser
from _pytest.deprecated import check_ispytest as check_ispytest
from _pytest.fixtures import FixtureRequest as FixtureRequest, fixture as fixture
from _pytest.main import Session as Session
from _pytest.store import StoreKey as StoreKey
from _pytest.terminal import TerminalReporter as TerminalReporter
from io import StringIO
from typing import AbstractSet, Any, Dict, Generator, List, Mapping, Optional, Tuple, TypeVar, Union

DEFAULT_LOG_FORMAT: str
DEFAULT_LOG_DATE_FORMAT: str
_ANSI_ESCAPE_SEQ: Any
caplog_handler_key: Any
caplog_records_key: Any

def _remove_ansi_escape_sequences(text: str) -> str: ...

class ColoredLevelFormatter(logging.Formatter):
    LOGLEVEL_COLOROPTS: Mapping[int, AbstractSet[str]] = ...
    LEVELNAME_FMT_REGEX: Any = ...
    _original_fmt: Any = ...
    _level_to_fmt_mapping: Any = ...
    def __init__(self, terminalwriter: TerminalWriter, *args: Any, **kwargs: Any) -> None: ...
    def format(self, record: logging.LogRecord) -> str: ...

class PercentStyleMultiline(logging.PercentStyle):
    _auto_indent: Any = ...
    def __init__(self, fmt: str, auto_indent: Union[int, str, bool, None]) -> None: ...
    @staticmethod
    def _update_message(record_dict: Dict[str, object], message: str) -> Dict[str, object]: ...
    @staticmethod
    def _get_auto_indent(auto_indent_option: Union[int, str, bool, None]) -> int: ...
    def format(self, record: logging.LogRecord) -> str: ...

def get_option_ini(config: Config, *names: str) -> Any: ...
def pytest_addoption(parser: Parser) -> None: ...
_HandlerType = TypeVar('_HandlerType', bound=logging.Handler)

class catching_logs:
    __slots__: Any = ...
    handler: Any = ...
    level: Any = ...
    def __init__(self, handler: _HandlerType, level: Optional[int]=...) -> None: ...
    orig_level: Any = ...
    def __enter__(self): ...
    def __exit__(self, type: Any, value: Any, traceback: Any) -> None: ...

class LogCaptureHandler(logging.StreamHandler):
    stream: StringIO
    records: Any = ...
    def __init__(self) -> None: ...
    def emit(self, record: logging.LogRecord) -> None: ...
    def reset(self) -> None: ...
    def handleError(self, record: logging.LogRecord) -> None: ...

class LogCaptureFixture:
    _item: Any = ...
    _initial_handler_level: Any = ...
    _initial_logger_levels: Any = ...
    def __init__(self, item: nodes.Node, *, _ispytest: bool=...) -> None: ...
    def _finalize(self) -> None: ...
    @property
    def handler(self) -> LogCaptureHandler: ...
    def get_records(self, when: str) -> List[logging.LogRecord]: ...
    @property
    def text(self) -> str: ...
    @property
    def records(self) -> List[logging.LogRecord]: ...
    @property
    def record_tuples(self) -> List[Tuple[str, int, str]]: ...
    @property
    def messages(self) -> List[str]: ...
    def clear(self) -> None: ...
    def set_level(self, level: Union[int, str], logger: Optional[str]=...) -> None: ...
    def at_level(self, level: int, logger: Optional[str]=...) -> Generator[None, None, None]: ...

def caplog(request: FixtureRequest) -> Generator[LogCaptureFixture, None, None]: ...
def get_log_level_for_setting(config: Config, *setting_names: str) -> Optional[int]: ...
def pytest_configure(config: Config) -> None: ...

class LoggingPlugin:
    _config: Any = ...
    formatter: Any = ...
    log_level: Any = ...
    caplog_handler: Any = ...
    report_handler: Any = ...
    log_file_level: Any = ...
    log_file_handler: Any = ...
    log_cli_level: Any = ...
    log_cli_handler: Any = ...
    def __init__(self, config: Config) -> None: ...
    def _create_formatter(self, log_format: Any, log_date_format: Any, auto_indent: Any): ...
    def set_log_path(self, fname: str) -> None: ...
    def _log_cli_enabled(self): ...
    def pytest_sessionstart(self) -> Generator[None, None, None]: ...
    def pytest_collection(self) -> Generator[None, None, None]: ...
    def pytest_runtestloop(self, session: Session) -> Generator[None, None, None]: ...
    def pytest_runtest_logstart(self) -> None: ...
    def pytest_runtest_logreport(self) -> None: ...
    def _runtest_for(self, item: nodes.Item, when: str) -> Generator[None, None, None]: ...
    def pytest_runtest_setup(self, item: nodes.Item) -> Generator[None, None, None]: ...
    def pytest_runtest_call(self, item: nodes.Item) -> Generator[None, None, None]: ...
    def pytest_runtest_teardown(self, item: nodes.Item) -> Generator[None, None, None]: ...
    def pytest_runtest_logfinish(self) -> None: ...
    def pytest_sessionfinish(self) -> Generator[None, None, None]: ...
    def pytest_unconfigure(self) -> None: ...

class _FileHandler(logging.FileHandler):
    def handleError(self, record: logging.LogRecord) -> None: ...

class _LiveLoggingStreamHandler(logging.StreamHandler):
    stream: TerminalReporter = ...
    capture_manager: Any = ...
    _test_outcome_written: bool = ...
    def __init__(self, terminal_reporter: TerminalReporter, capture_manager: Optional[CaptureManager]) -> None: ...
    _first_record_emitted: bool = ...
    def reset(self) -> None: ...
    _when: Any = ...
    _section_name_shown: bool = ...
    def set_when(self, when: Optional[str]) -> None: ...
    def emit(self, record: logging.LogRecord) -> None: ...
    def handleError(self, record: logging.LogRecord) -> None: ...

class _LiveLoggingNullHandler(logging.NullHandler):
    def reset(self) -> None: ...
    def set_when(self, when: str) -> None: ...
    def handleError(self, record: logging.LogRecord) -> None: ...
