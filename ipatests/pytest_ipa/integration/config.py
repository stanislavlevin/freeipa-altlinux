# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2013  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Utilities for configuration of multi-master tests"""
from __future__ import annotations

import logging
import random

import pytest
import pytest_multihost.config

from ipapython.dn import DN
from ipalib.constants import MAX_DOMAIN_LEVEL

from typing import TYPE_CHECKING, overload

if TYPE_CHECKING:
    from logging import Logger
    from typing import (
        Any,
        Dict,
        Iterable,
        List,
        Literal,
        Mapping,
        Type,
        Tuple,
        Set,
        Union,
        Sequence,
    )
    # currently exists only in stub file
    # pylint: disable=no-name-in-module
    from pytest_multihost.config import DomainDescriptionDict
    # pylint: enable=no-name-in-module

    from ipatests.pytest_ipa.integration.host import Host, WinHost
    IPA_HOST_ROLES = Literal["master", "replica", "client", "other"]
    AD_HOST_ROLES = Literal["ad", "ad_treedomain", "ad_subdomain"]


class Config(pytest_multihost.config.Config):
    extra_init_args = {
        'admin_name',
        'admin_password',
        'dirman_dn',
        'dirman_password',
        'nis_domain',
        'ntp_server',
        'ad_admin_name',
        'ad_admin_password',
        'dns_forwarder',
        'domain_level',
        'log_journal_since',
        'fips_mode',
    }

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault('test_dir', '/root/ipatests')
        self.domains: List[Domain]
        super(Config, self).__init__(**kwargs)

        admin_password: str = kwargs.get("admin_password", "Secret123")
        self.admin_name: str = kwargs.get("admin_name", "admin")
        self.admin_password = admin_password

        self.dirman_dn: DN = DN(
            kwargs.get("dirman_dn", "cn=Directory Manager")
        )
        self.dirman_password: str = kwargs.get(
            "dirman_password", admin_password
        )
        self.nis_domain: str = kwargs.get("nis_domain", "ipatest")
        self.ntp_server: str = kwargs.get(
            "ntp_server", "%s.pool.ntp.org" % random.randint(0, 3)
        )
        self.ad_admin_name: str = kwargs.get("ad_admin_name", "Administrator")
        self.ad_admin_password: str = kwargs.get(
            "ad_admin_password", "Secret123"
        )
        self.domain_level: int = kwargs.get("domain_level", MAX_DOMAIN_LEVEL)
        # 8.8.8.8 is probably the best-known public DNS
        self.dns_forwarder: str = kwargs.get("dns_forwarder", "8.8.8.8")
        self.debug = False
        self.log_journal_since: str = kwargs.get("log_journal_since", "-1h")
        if self.domain_level is None:
            self.domain_level = MAX_DOMAIN_LEVEL
        self.fips_mode: bool = kwargs.get("fips_mode", False)

    def get_domain_class(self) -> Type[Domain]:
        return Domain

    def get_logger(self, name: str) -> Logger:
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        return logger

    @property
    def ad_domains(self) -> List[Domain]:
        return [d for d in self.domains if d.is_ad_type]

    def get_all_hosts(self) -> Iterable[Union[Host, WinHost]]:
        for domain in self.domains:
            for host in domain.hosts:
                yield host

    def get_all_ipa_hosts(self) -> Iterable[Host]:
        from ipatests.pytest_ipa.integration.host import Host
        for ipa_domain in (d for d in self.domains if d.is_ipa_type):
            for ipa_host in ipa_domain.hosts:
                assert isinstance(ipa_host, Host)
                yield ipa_host

    def to_dict(
        self, _autosave_names: Union[Tuple[str, ...], Set[str]] = ()
    ) -> Dict[str, Any]:
        extra_args = self.extra_init_args - {'dirman_dn'}
        result = super(Config, self).to_dict(extra_args)
        result['dirman_dn'] = str(self.dirman_dn)
        return result

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Config:
        from ipatests.pytest_ipa.integration.env_config import config_from_env
        return config_from_env(env)

    def to_env(self, **kwargs: Any) -> Dict[str, str]:
        from ipatests.pytest_ipa.integration.env_config import config_to_env
        return config_to_env(self, **kwargs)

    def filter(self, descriptions: Sequence[DomainDescriptionDict]) -> None:
        """Destructively filters hosts and orders domains to fit description

        By default make_multihost_fixture() skips a test case, when filter()
        returns a FilterError. Let's turn FilterError into a fatal error
        instead.
        """
        try:
            super(Config, self).filter(descriptions)
        except pytest_multihost.config.FilterError as e:
            pytest.fail(str(e))


class Domain(pytest_multihost.config.Domain):
    """Configuration for an IPA / AD domain"""
    config: Config

    def __init__(self, config: Config, name: str, domain_type: str) -> None:
        self.type = str(domain_type)

        self.config = config
        self.name = str(name)
        self.hosts: List[Union[Host, WinHost]] = []

        assert self.is_ipa_type or self.is_ad_type
        self.realm = self.name.upper()
        self.basedn = DN(*(('dc', p) for p in name.split('.')))

    @property
    def is_ipa_type(self) -> bool:
        return self.type == 'IPA'

    @property
    def is_ad_type(self) -> bool:
        return self.type == 'AD' or self.type.startswith('AD_')

    @property
    def static_roles(self) -> Tuple[str, ...]:
        # Specific roles for each domain type are hardcoded
        if self.type == 'IPA':
            return ('master', 'replica', 'client', 'other')
        elif self.type == 'AD':
            return ('ad',)
        elif self.type == 'AD_SUBDOMAIN':
            return ('ad_subdomain',)
        elif self.type == 'AD_TREEDOMAIN':
            return ('ad_treedomain',)
        else:
            raise LookupError(self.type)

    def get_host_class(
        self,
        host_dict: Mapping[str, Any],
    ) -> Union[Type[Host], Type[WinHost]]:
        from ipatests.pytest_ipa.integration.host import Host, WinHost

        if self.is_ipa_type:
            return Host
        elif self.is_ad_type:
            return WinHost
        else:
            raise LookupError(self.type)

    # static roles

    @overload
    def host_by_role(
        self,
        role: IPA_HOST_ROLES,
    ) -> Host:
        ...

    @overload
    def host_by_role(
        self,
        role: AD_HOST_ROLES,
    ) -> WinHost:
        ...

    @overload
    def host_by_role(self, role: str) -> Union[Host, WinHost]:
        ...

    def host_by_role(self, role: str) -> Union[Host, WinHost]:
        return super().host_by_role(role)  # type: ignore[return-value]

    @overload
    def hosts_by_role(
        self,
        role: IPA_HOST_ROLES,
    ) -> Sequence[Host]:
        ...

    @overload
    def hosts_by_role(
        self,
        role: AD_HOST_ROLES,
    ) -> Sequence[WinHost]:
        ...

    @overload
    def hosts_by_role(self, role: str) -> Sequence[Union[Host, WinHost]]:
        ...

    def hosts_by_role(self, role: str) -> Sequence[Union[Host, WinHost]]:
        return super().hosts_by_role(role)  # type: ignore[return-value]

    @property
    def master(self) -> Host:
        return self.host_by_role("master")

    @property
    def masters(self) -> Sequence[Host]:
        return self.hosts_by_role('master')

    @property
    def replicas(self) -> Sequence[Host]:
        return self.hosts_by_role('replica')

    @property
    def clients(self) -> Sequence[Host]:
        return self.hosts_by_role('client')

    @property
    def ads(self) -> Sequence[WinHost]:
        return self.hosts_by_role('ad')

    @property
    def other_hosts(self) -> Sequence[Host]:
        return self.hosts_by_role('other')

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str],
        config: Config,
        index: int,
        domain_type: str,
    ) -> Domain:
        from ipatests.pytest_ipa.integration.env_config import domain_from_env
        return domain_from_env(env, config, index, domain_type)

    def to_env(self, **kwargs: Any) -> Dict[str, str]:
        from ipatests.pytest_ipa.integration.env_config import domain_to_env
        return domain_to_env(self, **kwargs)
