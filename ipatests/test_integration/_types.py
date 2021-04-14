#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#
"""Contains types used in annotations"""

from typing import Dict, List, Optional, TypedDict, TypeVar
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration.host import Host

IntegrationTest_T = TypeVar("IntegrationTest_T", bound=IntegrationTest)


class ResultDict(TypedDict):
    stdout: str
    stderr: str
    returncode: int


class ServiceDict(TypedDict, total=False):
    host: Host
    name: List[str]


class NetGroupDataDict(TypedDict):
    user: Dict[str, str]
    netgroup: str
    nested_netgroup: Optional[str]
    netgroup_nested_members: List[str]


class HostDict(TypedDict, total=False):
    name: str
    external_hostname: str
    ip: str
    role: str
    host_type: Optional[str]


class DomainDict(TypedDict):
    name: str
    type: str
    hosts: List[HostDict]


class ConfigDict(TypedDict, total=False):
    domains: List[DomainDict]
