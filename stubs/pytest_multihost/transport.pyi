from logging import Logger
from typing import Optional, Sequence, Union, overload

from pytest_multihost.util import TempDir
from pytest_multihost.host import BaseHost

class Transport:
    host: BaseHost
    logger_name: str
    log: Logger
    def __init__(self, host: BaseHost) -> None: ...
    def mkdir_recursive(self, path: str) -> None: ...
    def get_file(self, remotepath: str, localpath: str) -> None: ...
    def put_file(self, localpath: str, remotepath: str) -> None: ...

class OpenSSHTransport(Transport):
    def __init__(self, host: BaseHost) -> None: ...
    control_dir: TempDir
    def file_exists(self, path: str) -> bool: ...
    @overload
    def get_file_contents(
        self, filename: str, encoding: None = None
    ) -> bytes: ...
    @overload
    def get_file_contents(self, filename: str, encoding: str) -> str: ...
    def put_file_contents(
        self,
        filename: str,
        contents: Union[str, bytes],
        encoding: Optional[str] = "utf-8",
    ) -> None: ...
    def mkdir(self, path: str) -> None: ...
    def rmdir(self, path: str) -> None: ...
    def remove_file(self, filepath: str) -> None: ...
    def rename_file(self, oldpath: str, newpath: str) -> None: ...
    def start_shell(
        self,
        argv: Sequence[Union[str, bytes]],
        log_stdout: bool = True,
        encoding: str = "utf-8",
    ) -> SSHCommand: ...

class SSHCallWrapper:
    def __init__(self, command: List[str]) -> None: ...

class Command:
    log: Logger
    encoding: str
    raiseonerr: bool
    returncode: int
    stdout_text: str
    stderr_text: str
    def __init__(
        self,
        argv: Sequence[Union[str, bytes]],
        logger_name: Optional[str] = None,
        log_stdout: bool = True,
        get_logger: Optional[Callable[[Optional[str]], Logger]] = None,
        encoding: str = "utf-8",
    ) -> None: ...

    def wait(self, raiseonerr: object = DEFAULT) -> int: ...

class SSHCommand(Command):
    stdout_bytes: bytes
    stderr_bytes: bytes
    def __init__(
        self,
        ssh: SSHCallWrapper,
        argv: Sequence[Union[str, bytes]],
        logger_name: Optional[str],
        log_stdout: bool = True,
        collect_output: bool = True,
        encoding: str = "utf-8",
        get_logger: Optional[Callable[[Optional[str]], Logger]] = None,
    ) -> None: ...
