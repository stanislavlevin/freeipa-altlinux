# Authors:
#   Petr Viktorin <pviktori@redhat.com>
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

"""Base class for FreeIPA integration tests"""
from __future__ import annotations

import pytest
import subprocess

from ipatests.pytest_ipa.integration import tasks
from pytest_sourceorder import ordered

from typing import Iterable, Optional, List, Sequence, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from ipatests.pytest_ipa.integration.host import Host, WinHost
    from ipatests.pytest_ipa.integration.config import (
        Domain, IPA_HOST_ROLES, AD_HOST_ROLES
    )
    from ipatests.pytest_ipa.integration._types import (
        IpaMHFixture,
        HOST_LOGS_ATYPE,
    )

@ordered
@pytest.mark.usefixtures('mh')
@pytest.mark.usefixtures('integration_logs')
class IntegrationTest:
    num_replicas = 0
    num_clients = 0
    num_ad_domains = 0
    num_ad_subdomains = 0
    num_ad_treedomains = 0
    required_extra_roles: List[str] = []
    topology: Optional[str] = None
    domain_level: Optional[int] = None
    fips_mode: Optional[bool] = None
    master: Host
    clients: List[Host]
    replicas: List[Host]
    domain: Domain
    logs_to_collect: HOST_LOGS_ATYPE

    ad_domains: List[Domain]
    ads: List[WinHost]
    ad_subdomains: Sequence[WinHost]
    ad_treedomains: Sequence[WinHost]

    @classmethod
    def get_all_hosts_(cls) -> Iterable[Union[Host, WinHost]]:
        return cls.domain.config.get_all_hosts()

    @classmethod
    def get_all_ipa_hosts(cls) -> Iterable[Host]:
        return cls.domain.config.get_all_ipa_hosts()

    @classmethod
    def get_domains(cls) -> List[Domain]:
        return [cls.domain] + cls.ad_domains

    @classmethod
    def enable_fips_mode(cls) -> None:
        for host in cls.get_all_ipa_hosts():
            if not host.is_fips_mode:
                host.enable_userspace_fips()

    @classmethod
    def disable_fips_mode(cls) -> None:
        for host in cls.get_all_ipa_hosts():
            if host.is_userspace_fips:
                host.disable_userspace_fips()

    @classmethod
    def install(cls, mh: IpaMHFixture) -> None:
        if cls.domain_level is not None:
            domain_level = cls.domain_level
        else:
            domain_level = cls.master.config.domain_level

        if cls.master.config.fips_mode:  # pylint: disable=using-constant-test
            cls.fips_mode = True
        if cls.fips_mode:
            cls.enable_fips_mode()

        if cls.topology is None:
            return
        else:
            tasks.install_topo(cls.topology,
                               cls.master, cls.replicas,
                               cls.clients, domain_level)
    @classmethod
    def uninstall(cls, mh: IpaMHFixture) -> None:
        for replica in cls.replicas:
            try:
                tasks.run_server_del(
                    cls.master, replica.hostname, force=True,
                    ignore_topology_disconnect=True, ignore_last_of_role=True)
            except subprocess.CalledProcessError:
                # If the master has already been uninstalled,
                # this call may fail
                pass
            tasks.uninstall_master(replica)
        tasks.uninstall_master(cls.master)
        for client in cls.clients:
            tasks.uninstall_client(client)
        if cls.fips_mode:
            cls.disable_fips_mode()
