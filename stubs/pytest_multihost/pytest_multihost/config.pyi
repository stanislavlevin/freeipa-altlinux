from logging import Logger
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Set,
    Type,
    TypeVar,
    Tuple,
    Union,
    Sequence,
    TypedDict,
)

from pytest_multihost.host import BaseHost

Domain_T = TypeVar("Domain_T", bound="Domain")
Config_T = TypeVar("Config_T", bound="Config")

class DomainDescriptionDict(TypedDict):
    type: str
    hosts: Dict[str, int]

class DomainDict(TypedDict):
    type: str
    hosts: Dict[str, int]
    name: str

class FilterError(ValueError): ...

class Config:
    log: Logger
    extra_init_args: Iterable
    test_dir: str
    ssh_key_filename: str
    ssh_password: str
    ssh_username: str
    ipv6: bool
    windows_test_dir: str
    domains: Sequence[Domain]
    def __init__(self, **kwargs: Any) -> None: ...
    def get_domain_class(self) -> Type[Domain]: ...
    def get_logger(self, name: str) -> Logger: ...
    def host_by_name(self, name: str) -> BaseHost: ...
    @classmethod
    def from_dict(
        cls: Type[Config_T], dct: Mapping[str, Any]
    ) -> Config_T: ...
    def to_dict(
        self, _autosave_names: Union[Tuple[str, ...], Set[str]] = ()
    ) -> Dict[str, Any]: ...
    def filter(
        self, descriptions: Sequence[DomainDescriptionDict]
    ) -> None: ...

class Domain:
    log: Logger
    type: str
    config: Config
    name: str
    hosts: Sequence[BaseHost]
    def __init__(
        self, config: Config, name: str, domain_type: str
    ) -> None: ...
    def get_host_class(
        self, host_dict: Mapping[str, Any]
    ) -> Type[BaseHost]: ...
    @property
    def host_classes(self) -> Dict[str, BaseHost]: ...
    @property
    def roles(self) -> Set[str]: ...
    @property
    def extra_roles(self) -> List[str]: ...
    @property
    def static_roles(self) -> Tuple[str, ...]: ...
    def host_by_role(self, role: str) -> BaseHost: ...
    def hosts_by_role(self, role: str) -> Sequence[BaseHost]: ...
    def host_by_name(self, name: str) -> BaseHost: ...
    def filter(self, host_counts: Mapping[str, int]) -> None: ...
    def fits(self, description: DomainDescriptionDict) -> bool: ...
    @classmethod
    def from_dict(
        cls: Type[Domain_T], dct: DomainDict, config: Config
    ) -> Domain_T: ...
    def to_dict(self) -> DomainDict: ...
