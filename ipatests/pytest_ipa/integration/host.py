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

"""Host class for integration testing"""
from __future__ import annotations

import re
import subprocess
import tempfile

import ldap
import pytest_multihost.host

from ipapython import ipaldap

from .fips import (
    is_fips_enabled, enable_userspace_fips, disable_userspace_fips
)
from .host_ipaplatform import HostIPAPlatform
from .host_systemctl import HostSystemctl
from .transport import IPAOpenSSHTransport
from .resolver import resolver

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import (
        Any, Dict, Iterable, List, Mapping, Optional, Type, Union
    )
    from ldap.ldapobject import SimpleLDAPObject
    from pytest_multihost.transport import SSHCommand
    from .config import Config, Domain
    from .expect import IpaTestExpect
    from .resolver import (
        ResolvedResolver, NetworkManagerResolver, PlainFileResolver
    )
    from ._types import SSHCOMMAND_ARGV_TYPE

FIPS_NOISE_RE = re.compile(br"FIPS mode initialized\r?\n?")


class LDAPClientWithoutCertCheck(ipaldap.LDAPClient):
    """Adds an option to disable certificate check for TLS connection

    To disable certificate validity check create client with added option
    no_certificate_check:
    client = LDAPClientWithoutCertCheck(..., no_certificate_check=True)
    """
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._no_certificate_check = kwargs.pop(
            'no_certificate_check', False)
        super(LDAPClientWithoutCertCheck, self).__init__(*args, **kwargs)

    def _connect(self) -> SimpleLDAPObject:
        if (self._start_tls and self.protocol == 'ldap' and
                self._no_certificate_check):
            with self.error_handler():
                conn = ipaldap.ldap_initialize(
                    self.ldap_uri, cacertfile=self._cacert)
                conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT,
                                ldap.OPT_X_TLS_NEVER)
                conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
                conn.start_tls_s()
                return conn
        else:
            return super(LDAPClientWithoutCertCheck, self)._connect()


class Host(pytest_multihost.host.Host):
    """Representation of a remote IPA host"""

    transport_class = IPAOpenSSHTransport

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
    ) -> None:
        super().__init__(
            domain, hostname, role, ip=ip,
            external_hostname=external_hostname, username=username,
            password=password, test_dir=test_dir, host_type=host_type
        )
        self.domain: Domain
        self._fips_mode: Optional[bool] = None
        self._selinux_enabled: Optional[bool] = None
        self._is_selinux_enforced: Optional[bool] = None
        self._userspace_fips = False
        self._ipaplatform: Optional[HostIPAPlatform] = None
        self._systemctl: Optional[HostSystemctl] = None
        self._ds_serverid: Optional[str] = None
        self._resolver: Union[
            ResolvedResolver, NetworkManagerResolver, PlainFileResolver, None
        ] = None

    @property
    def transport(self) -> IPAOpenSSHTransport:
        # mypy: ignore return value until pytest_multihost add annotations
        return super().transport  # type: ignore[return-value]

    @property
    def config(self) -> Config:
        # mypy: ignore return value until pytest_multihost add annotations
        return super().config  # type: ignore[return-value]

    @property
    def resolver(self) -> Union[
        ResolvedResolver, NetworkManagerResolver, PlainFileResolver
    ]:
        if self._resolver is None:
            self._resolver = resolver(self)
        return self._resolver

    @property
    def ipaplatform(self) -> HostIPAPlatform:
        if self._ipaplatform is None:
            self._ipaplatform = HostIPAPlatform(self.run_command)
        return self._ipaplatform

    def invalidate_ipaplatform(self) -> None:
        """Invalidate ipaplatform cache, next call will re-read ipaplatform"""
        self._ipaplatform = None

    @property
    def systemctl(self) -> HostSystemctl:
        if self._systemctl is None:
            self._systemctl = HostSystemctl(self)
        return self._systemctl

    @property
    def ds_serverid(self) -> str:
        """389-DS server id"""
        if self._ds_serverid is None:
            self._ds_serverid = self.run_command(
                [
                    "python3",
                    "-c",
                    (
                        "from ipapython.ipaldap import realm_to_serverid;"
                        f"print(realm_to_serverid('{self.domain.realm}'))"
                    ),
                ],
                log_stdout=False,
            ).stdout_text.rstrip()
        return self._ds_serverid

    @property
    def is_fips_mode(self) -> bool:
        """Check and cache if a system is in FIPS mode
        """
        if self._fips_mode is None:
            self._fips_mode = is_fips_enabled(self)
        return self._fips_mode

    @property
    def is_selinux_enabled(self) -> bool:
        if self._selinux_enabled is None:
            result = self.run_command(
                [self.ipaplatform.paths.SELINUXENABLED],
                raiseonerr=False,
            )
            self._selinux_enabled = result.returncode == 0

        return self._selinux_enabled

    @property
    def is_selinux_enforced(self) -> bool:
        if self._is_selinux_enforced is None:
            if not self.is_selinux_enabled:
                self._is_selinux_enforced = False
            else:
                result = self.run_command(
                    [self.ipaplatform.paths.GETENFORCE],
                    raiseonerr=False,
                )
                self._is_selinux_enforced = "Enforcing" in result.stdout_text

        return self._is_selinux_enforced

    @property
    def is_userspace_fips(self) -> bool:
        """Check if host uses fake userspace FIPS
        """
        return self._userspace_fips

    def enable_userspace_fips(self) -> bool:
        """Enable fake userspace FIPS mode

        The call has no effect if the system is already in FIPS mode.

        :return: True if system was modified, else None
        """
        if not self.is_fips_mode:
            enable_userspace_fips(self)
            self._fips_mode = True
            self._userspace_fips = True
            return True
        else:
            return False

    def disable_userspace_fips(self) -> bool:
        """Disable fake userspace FIPS mode

        The call has no effect if userspace FIPS mode is not enabled.

        :return: True if system was modified, else None
        """
        if self.is_userspace_fips:
            disable_userspace_fips(self)
            self._userspace_fips = False
            self._fips_mode = False
            return True
        else:
            return False

    @staticmethod
    def _make_host(
        domain: Domain,
        hostname: str,
        role: str,
        ip: str,
        external_hostname: str,
    ) -> Union[Host, WinHost]:
        # We need to determine the type of the host, this depends on the domain
        # type, as we assume all Unix machines are in the Unix domain and
        # all Windows machine in a AD domain

        if domain.type == 'AD':
            cls: Union[Type[Host], Type[WinHost]] = WinHost
        else:
            cls = Host

        return cls(
            domain,
            hostname,
            role,
            ip=ip,
            external_hostname=external_hostname
        )

    def ldap_connect(self) -> LDAPClientWithoutCertCheck:
        """Return an LDAPClient authenticated to this host as directory manager
        """
        self.log.info('Connecting to LDAP at %s', self.external_hostname)
        # get IPA CA cert to establish a secure connection
        cacert = self.get_file_contents(self.ipaplatform.paths.IPA_CA_CRT)
        with tempfile.NamedTemporaryFile() as f:
            f.write(cacert)
            f.flush()

            hostnames_mismatch = self.hostname != self.external_hostname
            conn = LDAPClientWithoutCertCheck.from_hostname_secure(
                self.external_hostname,
                cacert=f.name,
                no_certificate_check=hostnames_mismatch)
            binddn = self.config.dirman_dn
            self.log.info('LDAP bind as %s', binddn)
            conn.simple_bind(binddn, self.config.dirman_password)

            # The CA cert file  has been loaded into the SSL_CTX and is no
            # longer required.

        return conn

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str],
        domain: Domain,
        hostname: str,
        role: str,
        index: int,
        domain_index: int,
    ) -> Union[Host, WinHost]:
        from ipatests.pytest_ipa.integration.env_config import host_from_env
        return host_from_env(env, domain, hostname, role, index, domain_index)

    def to_env(self, **kwargs: Any) -> Dict[str, str]:
        from ipatests.pytest_ipa.integration.env_config import host_to_env
        return host_to_env(self, **kwargs)

    def run_command(
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
        """Wrapper around run_command to log stderr on raiseonerr=True

        :param ok_returncode: return code considered to be correct,
                              you can pass an integer or sequence of integers
        """
        if isinstance(ok_returncode, int):
            ok_returncodes = [ok_returncode]
        elif isinstance(ok_returncode, (list, tuple)):
            ok_returncodes = list(ok_returncode)
        else:
            raise TypeError(
                "ok_returncode must be an integer or sequence of integers;"
                "got %r" % ok_returncode
            )

        result = super().run_command(
            argv, set_env=set_env, stdin_text=stdin_text,
            log_stdout=log_stdout, raiseonerr=False, cwd=cwd, bg=bg,
            encoding=encoding
        )
        # in FIPS mode SSH may print noise to stderr, remove the string
        # "FIPS mode initialized" + optional newline.
        result.stderr_bytes = FIPS_NOISE_RE.sub(b'', result.stderr_bytes)
        result_ok = result.returncode in ok_returncodes

        if not result_ok and raiseonerr:
            result.log.error('stderr: %s', result.stderr_text)
            raise subprocess.CalledProcessError(
                result.returncode, argv,
                result.stdout_text, result.stderr_text
            )
        else:
            return result

    def spawn_expect(
        self,
        argv: Union[str, List[str]],
        default_timeout: int = 10,
        encoding: Optional[str] = "utf-8",
        extra_ssh_options: Optional[List[str]] = None,
    ) -> IpaTestExpect:
        """Run command on remote host using IpaTestExpect"""
        return self.transport.spawn_expect(argv, default_timeout, encoding,
                                           extra_ssh_options)

class WinHost(pytest_multihost.host.WinHost):
    """
    Representation of a remote Windows host.

    This serves as a sketch class once we move from manual preparation of
    Active Directory to the automated setup.
    """
    transport_class = IPAOpenSSHTransport

    def __init__(
        self, domain: Domain, hostname: str, role: str, **kwargs: Any,
    ) -> None:
        self.domain: Domain
        super().__init__(domain, hostname, role, **kwargs)
