from logging import Logger
from typing import (
    Callable, Optional, Sequence, Type, TypedDict, Union, overload
)

from pytest_multihost.config import Config, Domain
from pytest_multihost.transport import SSHCommand, OpenSSHTransport

LogCollector: Callable[[BaseHost, str], None]
Host_T = TypeVar("Host_T", bound="BaseHost")

class HostDescriptionDictOut(TypedDict, total=False):
    host_type: str
    name: str
    role: str
    ip: Optional[str]
    external_hostname: Optional[str]

class HostDescriptionDictIn(HostDescriptionDictOut, total=False):
    username: Optional[str]
    password: Optional[str]

class BaseHost:
    command_prelude: bytes
    hostname: str
    external_hostname: str
    shortname: str
    host_type: str
    domain: Domain
    role: str
    ssh_username: str
    ssh_password: str
    ssh_key_filename: str
    ssh_port: int
    test_dir: str
    netbios: str
    logger_name: str
    log: Logger
    ip: str
    env_sh_path: str
    log_collectors: List[LogCollector]
    transport_class: Type[OpenSSHTransport]

    def __init__(
        self,
        domain: Domain,
        hostname: str,
        role: str,
        ip: Optional[str] = None,
        external_hostname: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        test_dir: Optional[str] = None,
        host_type: Optional[str] = None,
    ) -> None: ...
    def run_command(
        self,
        argv: Union[str, Sequence[Union[str, bytes]]],
        set_env: bool = ...,
        stdin_text: Optional[str] = ...,
        log_stdout: bool = ...,
        raiseonerr: bool = ...,
        cwd: Optional[str] = ...,
        bg: bool = ...,
        encoding: str = ...,
    ) -> SSHCommand: ...
    @property
    def config(self) -> Config: ...
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
    @property
    def transport(self) -> OpenSSHTransport: ...
    def add_log_collector(self, collector: LogCollector) -> None: ...
    def remove_log_collector(self, collector: LogCollector) -> None: ...
    def collect_log(self, filename: str) -> None: ...
    def reset_connection(self) -> None: ...
    @classmethod
    def from_dict(
        cls: Type[Host_T],
        dct: Union[str, HostDescriptionDictIn],
        domain: Domain,
    ) -> Host_T: ...
    def to_dict(self) -> HostDescriptionDictOut: ...

class Host(BaseHost): ...
class WinHost(BaseHost):
    def __init__(
        self, domain: Domain, hostname: str, role: str, **kwargs: Any
    ) -> None: ...
