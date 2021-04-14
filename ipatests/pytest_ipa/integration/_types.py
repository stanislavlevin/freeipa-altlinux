#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#
"""Contains types used in annotations

Imported values to a module are not treated as exported and mypy doesn't
allow other modules to import them. mypy will not re-export unless the
item is imported using from-as or is included in __all__.
"""
from ipatests.pytest_ipa.integration.host import Host, WinHost
from ipatests.pytest_ipa.integration.config import Config, Domain

from typing import (
    Dict,
    Iterable,
    Protocol,
    List,
    Mapping,
    Optional,
    Union,
    Sequence,
    TypedDict,
)
from pytest_multihost.plugin import MultihostFixture
from pytest_multihost.transport import SSHCommand

SSHCOMMAND_ARGV_TYPE = Union[str, Sequence[Union[str, bytes]]]


class RunCommandCb(Protocol):
    def __call__(
        self,
        argv: SSHCOMMAND_ARGV_TYPE,
        set_env: bool = True,
        stdin_text: Optional[str] = None,
        log_stdout: bool = True,
        raiseonerr: bool = True,
        cwd: Optional[str] = None,
        bg: bool = False,
        encoding: str = "utf-8",
        ok_returncode: Union[int, Iterable[int]] = 0,
    ) -> SSHCommand:
        ...


class ResolverState(TypedDict):
    pass


class ResolvedState(ResolverState):
    resolved_config: Optional[str]


class ResolvConfState(ResolverState):
    resolv_conf: str


class NMState(ResolverState):
    nm_config: Optional[str]


class TopoNodeDict(TypedDict):
    name: str
    rightnode: str
    leftnode: str


HOST_LOGS_RTYPE = Dict[Host, List[str]]
HOST_LOGS_ATYPE = Mapping[Host, Iterable[str]]


class IpaMHFixture(MultihostFixture):
    config: Config
    domain: Domain
    master: Host
    clients: Sequence[Host]
    replicas: Sequence[Host]
    ad_domains: Sequence[Domain]
    ads: Sequence[WinHost]
    ad_subdomains: Sequence[WinHost]
    ad_treedomains: Sequence[WinHost]


class HostPlatformService:
    service_name: str
    systemd_name: str
