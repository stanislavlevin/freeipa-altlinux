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

"""Common tasks for FreeIPA integration tests"""

from __future__ import annotations

from collections import OrderedDict
import logging
import os
from io import StringIO
import textwrap
import re
import itertools
import shlex
import subprocess
import time
from pipes import quote
import configparser
from contextlib import contextmanager
# mypy reexport if import x as y
from pkg_resources import parse_version as parse_version
import uuid

import dns
from ldif import LDIFWriter
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

from ipapython import certdb
from ipapython import ipautil
from ipapython.dnsutil import DNSResolver
from ipapython.dn import DN
from ipalib import errors
from ipalib.util import get_reverse_zone_default
from ipalib.constants import (
    DEFAULT_CONFIG, DOMAIN_SUFFIX_NAME, DOMAIN_LEVEL_0,
    MIN_DOMAIN_LEVEL, MAX_DOMAIN_LEVEL
)

from ipatests.create_external_ca import ExternalCA
from .base_tasks import create_temp_file
from .env_config import env_to_script
from .host import Host
from .firewall import Firewall
from .resolver import ResolvedResolver
from .sssd import (
    setup_sssd_conf, clear_sssd_cache, check_if_sssd_is_online
)

from typing import NamedTuple, TYPE_CHECKING, overload

if TYPE_CHECKING:
    from types import TracebackType
    from typing import (
        Any,
        Callable,
        Dict,
        Iterable,
        Iterator,
        List,
        Literal,
        Optional,
        Pattern,
        Mapping,
        Sequence,
        Tuple,
        Type,
        TypeVar,
        Union,
    )
    from configparser import RawConfigParser

    # pkg_resources manually reload bundled packages
    # pylint: disable=no-name-in-module,import-error
    from pkg_resources.extern.packaging.version import Version
    # pylint: enable=no-name-in-module,import-error

    from cryptography.x509.base import Certificate
    from cryptography.x509.extensions import ExtensionType
    from pytest_multihost.transport import SSHCommand
    from ldap.ldapobject import LDAPObject

    from .config import Domain
    from .host import WinHost, LDAPClientWithoutCertCheck
    from ipatests.test_integration._types import IntegrationTest_T
    from ._types import TopoNodeDict, SSHCOMMAND_ARGV_TYPE

    TOPO_CALLABLE_T = Callable[[Any, Sequence[Any]], Iterator[Tuple[Any, ...]]]
    TOPO_WRAPPER_T = TypeVar(
        "TOPO_WRAPPER_T",
        bound=TOPO_CALLABLE_T,
    )
    TOPO_ITER_HOST_T = Iterator[Tuple[Host, Host]]
    CHECK_ARGS_T = TypeVar('CHECK_ARGS_T', bound=Callable[..., Any])


logger = logging.getLogger(__name__)


def check_arguments_are(
    args_slice: Tuple[int, int], instanceof: Type[Any]
) -> Callable[[CHECK_ARGS_T], CHECK_ARGS_T]:
    """
    :param: slice - tuple of integers denoting the beginning and the end
    of argument list to be checked
    :param: instanceof - name of the class the checked arguments should be
    instances of
    Example: @check_arguments_are((1, 3), int) will check that the second
    and third arguments are integers
    """
    def wrapper(func: CHECK_ARGS_T) -> CHECK_ARGS_T:
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            for i in args[args_slice[0]:args_slice[1]]:
                assert isinstance(i, instanceof), "Wrong type: %s: %s" % (
                    i, type(i))
            return func(*args, **kwargs)
        # don't want to use 'cast' here to avoid extra typing deps at runtime
        return wrapped  # type: ignore[return-value]
    return wrapper


def prepare_reverse_zone(host: Host, ip: str) -> Tuple[str, int]:
    zone = get_reverse_zone_default(ip)
    result = host.run_command(
        ["ipa", "dnszone-add", zone, '--skip-overlap-check'],
        raiseonerr=False
    )
    if result.returncode > 0:
        logger.warning("%s", result.stderr_text)
    return zone, result.returncode


def prepare_host(host: Union[Host, WinHost]) -> None:
    if isinstance(host, Host):
        env_filename = os.path.join(host.config.test_dir, 'env.sh')

        # First we try to run simple echo command to test the connection
        host.run_command(['true'], set_env=False)
        try:
            host.transport.mkdir_recursive(host.config.test_dir)
        except IOError:
            # The folder already exists
            pass
        host.put_file_contents(env_filename, env_to_script(host.to_env()))


def rpcbind_kadmin_workaround(host: Host) -> None:
    """Restart rpcbind in case it blocks 749/TCP, 464/UDP, or 464/TCP

    See https://pagure.io/freeipa/issue/7769
    See https://bugzilla.redhat.com/show_bug.cgi?id=1592883
    """
    cmd = [
        'ss',
        '--all',  # listening and non-listening sockets
        '--tcp', '--udp',  # only TCP and UDP sockets
        '--numeric',  # don't resolve host and service names
        '--processes',  # show processes
    ]
    # run once to list all ports for debugging
    host.run_command(cmd)
    # check for blocked kadmin port
    cmd.extend((
        '-o', 'state', 'all',  # ports in any state, not just listening
        '( sport = :749 or dport = :749 or sport = :464 or dport = :464 )'
    ))
    for _i in range(5):
        result = host.run_command(cmd)
        if 'rpcbind' in result.stdout_text:
            logger.error("rpcbind blocks 749, restarting")
            host.systemctl.restart("rpcbind")
            time.sleep(2)
        else:
            break


def disable_systemd_resolved_cache(host: Host) -> None:
    if not ResolvedResolver.is_our_resolver(host):
        return
    resolved_conf_file = (
        '/etc/systemd/resolved.conf.d/zzzz-ipatests-disable-cache.conf')
    resolved_conf = textwrap.dedent('''
        # generated by IPA tests
        [Resolve]
        Cache=no
    ''')
    host.run_command(['mkdir', '-p', os.path.dirname(resolved_conf_file)])
    host.put_file_contents(resolved_conf_file, resolved_conf)
    host.systemctl.restart("systemd-resolved")


def apply_common_fixes(host: Host) -> None:
    prepare_host(host)
    fix_hostname(host)
    rpcbind_kadmin_workaround(host)
    disable_systemd_resolved_cache(host)


def prepare_dse_changes(host: Host, log_level: int = 8192) -> str:
    """Put custom changes for dse.ldif on the host
    """
    ipatests_dse_path = os.path.join(host.config.test_dir, "ipatests_dse.ldif")
    ldif = textwrap.dedent(
        """\
        # replication debugging
        dn: cn=config
        changetype: modify
        replace: nsslapd-errorlog-level
        nsslapd-errorlog-level: {log_level}

        # server writes all access log entries directly to disk
        dn: cn=config
        changetype: modify
        replace: nsslapd-accesslog-logbuffering
        nsslapd-accesslog-logbuffering: off
        """
    ).format(log_level=log_level)
    host.put_file_contents(ipatests_dse_path, ldif)
    return ipatests_dse_path


def allow_sync_ptr(host: Host) -> None:
    kinit_admin(host)
    host.run_command(["ipa", "dnsconfig-mod", "--allow-sync-ptr=true"],
                     raiseonerr=False)


def backup_file(host: Host, filename: str) -> bool:
    if host.transport.file_exists(filename):
        backupname = os.path.join(host.config.test_dir, 'file_backup',
                                  filename.lstrip('/'))
        host.transport.mkdir_recursive(os.path.dirname(backupname))
        host.run_command(['cp', '-af', filename, backupname])
        return True
    else:
        rmname = os.path.join(host.config.test_dir, 'file_remove')
        host.run_command('echo %s >> %s' % (
            ipautil.shell_quote(filename),
            ipautil.shell_quote(rmname)))
        host.transport.mkdir_recursive(os.path.dirname(rmname))
        return False


def fix_hostname(host: Host) -> None:
    backup_file(host, host.ipaplatform.paths.ETC_HOSTNAME)
    host.put_file_contents(
        host.ipaplatform.paths.ETC_HOSTNAME, host.hostname + "\n"
    )
    host.run_command(['hostname', host.hostname])

    backupname = os.path.join(host.config.test_dir, 'backup_hostname')
    host.run_command('hostname > %s' % ipautil.shell_quote(backupname))


def fix_apache_semaphores(master: Host) -> None:
    systemd_available = master.transport.file_exists(
        master.ipaplatform.paths.SYSTEMCTL
    )

    if systemd_available:
        master.systemctl.stop("httpd")
    else:
        master.run_command(
            [master.ipaplatform.paths.SBIN_SERVICE, 'httpd', 'stop'],
            raiseonerr=False,
        )

    master.run_command(
        'for line in `ipcs -s | grep apache ''| cut -d " " -f 2`; '
        'do ipcrm -s $line; done', raiseonerr=False
    )


def unapply_fixes(host: Host) -> None:
    restore_files(host)
    restore_hostname(host)
    # Clean ccache to prevent issues like 5741
    host.run_command(['kdestroy', '-A'], raiseonerr=False)

    # Clean up the test directory
    host.run_command(['rm', '-rvf', host.config.test_dir])


def restore_files(host: Host) -> None:
    backupname = os.path.join(host.config.test_dir, 'file_backup')
    rmname = os.path.join(host.config.test_dir, 'file_remove')

    # Prepare command for restoring context of the backed-up files
    sed_remove_backupdir = 's/%s//g' % backupname.replace('/', r'\/')
    restorecon_command = (
        "find %s | "
        "sed '%s' | "
        "sed '/^$/d' | "
        "xargs -d '\n' "
        "/sbin/restorecon -v" % (backupname, sed_remove_backupdir))

    # Prepare command for actual restoring of the backed up files
    copyfiles_command = 'if [ -d %(dir)s/ ]; then cp -arvf %(dir)s/* /; fi' % {
        'dir': ipautil.shell_quote(backupname)}

    # Run both commands in one session. For more information, see:
    # https://fedorahosted.org/freeipa/ticket/4133
    host.run_command('%s ; (%s ||:)' % (copyfiles_command, restorecon_command))

    # Remove all the files that did not exist and were 'backed up'
    host.run_command(['xargs', '-d', r'\n', '-a', rmname, 'rm', '-vf'],
                     raiseonerr=False)
    host.run_command(['rm', '-rvf', backupname, rmname], raiseonerr=False)


def restore_hostname(host: Host) -> None:
    backupname = os.path.join(host.config.test_dir, 'backup_hostname')
    try:
        hostname = host.get_file_contents(backupname, encoding='utf-8')
    except IOError:
        logger.debug('No hostname backed up on %s', host.hostname)
    else:
        host.run_command(['hostname', hostname.strip()])
        host.run_command(['rm', backupname])


def enable_ds_audit_log(host: Host, enabled: Literal["on", "off"]) -> None:
    """Enable 389-ds audit log and auditfail log

    :param host: the host on which audit log is configured
    :param enabled: a string (either 'on' or 'off')
    """
    logger.info('Set LDAP audit log')
    if enabled not in ["on", "off"]:
        raise ValueError("'enabled' should be either 'on' or 'off'")

    logging_ldif = textwrap.dedent("""
        dn: cn=config
        changetype: modify
        replace: nsslapd-auditlog-logging-enabled
        nsslapd-auditlog-logging-enabled: {enabled}
        -
        replace: nsslapd-auditfaillog-logging-enabled
        nsslapd-auditfaillog-logging-enabled: {enabled}
        """.format(enabled=enabled))
    ldapmodify_dm(host, logging_ldif)


def set_default_ttl_for_ipa_dns_zone(
    host: Host,
    raiseonerr: bool = True,
) -> None:
    args = [
        'ipa', 'dnszone-mod', host.domain.name,
        '--default-ttl', '1',
        '--ttl', '1'
    ]
    result = host.run_command(args, raiseonerr=raiseonerr, stdin_text=None)
    if result.returncode != 0:
        logger.info('Failed to set TTL and default TTL for DNS zone %s to 1',
                    host.domain.name)


def install_master(
    host: Host,
    setup_dns: bool = True,
    setup_kra: bool = False,
    setup_adtrust: bool = False,
    extra_args: Iterable[str] = (),
    domain_level: Optional[int] = None,
    unattended: bool = True,
    external_ca: bool = False,
    stdin_text: Optional[str] = None,
    raiseonerr: bool = True,
) -> SSHCommand:
    if domain_level is None:
        domain_level = host.config.domain_level
    check_domain_level(domain_level)
    apply_common_fixes(host)
    if "--dirsrv-config-file" not in extra_args:
        ipatests_dse: Optional[str] = prepare_dse_changes(host)
    else:
        ipatests_dse = None
    fix_apache_semaphores(host)
    fw = Firewall(host)
    fw_services = ["freeipa-ldap", "freeipa-ldaps"]

    args = [
        'ipa-server-install',
        '-n', host.domain.name,
        '-r', host.domain.realm,
        '-p', host.config.dirman_password,
        '-a', host.config.admin_password,
        "--domain-level=%i" % domain_level,
    ]
    if ipatests_dse:
        args.extend(["--dirsrv-config-file", ipatests_dse])

    if unattended:
        args.append('-U')

    if setup_dns:
        args.extend([
            '--setup-dns',
            '--forwarder', host.config.dns_forwarder,
            '--auto-reverse'
        ])
        fw_services.append("dns")
    if setup_kra:
        args.append('--setup-kra')
    if setup_adtrust:
        args.append('--setup-adtrust')
        fw_services.append("freeipa-trust")
    if external_ca:
        args.append('--external-ca')

    args.extend(extra_args)
    result = host.run_command(args, raiseonerr=raiseonerr,
                              stdin_text=stdin_text)
    if result.returncode == 0:
        fw.enable_services(fw_services)
    if result.returncode == 0 and not external_ca:
        # external CA step 1 doesn't have DS and KDC fully configured, yet
        enable_ds_audit_log(host, 'on')
        setup_sssd_conf(host)
        kinit_admin(host)
        if setup_dns:
            setup_named_debugging(host)
            # fixup DNS zone default TTL for IPA DNS zone
            # For tests we should not wait too long
            set_default_ttl_for_ipa_dns_zone(host, raiseonerr=raiseonerr)
    return result


def check_domain_level(domain_level: int) -> None:
    if domain_level < MIN_DOMAIN_LEVEL:
        pytest.fail(
            "Domain level {} not supported, min level is {}.".format(
                domain_level, MIN_DOMAIN_LEVEL)
        )
    if domain_level > MAX_DOMAIN_LEVEL:
        pytest.fail(
            "Domain level {} not supported, max level is {}.".format(
                domain_level, MAX_DOMAIN_LEVEL)
        )


def domainlevel(host: Host) -> int:
    """
    Dynamically determines the domainlevel on master. Needed for scenarios
    when domainlevel is changed during the test execution.

    Sometimes the master is even not installed. Please refer to ca-less
    tests, where we call tasks.uninstall_master after every test while a lot
    of them make sure that the server installation fails. Therefore we need
    to not raise on failures here.
    """
    kinit_admin(host, raiseonerr=False)
    result = host.run_command(['ipa', 'domainlevel-get'], raiseonerr=False)
    level = MIN_DOMAIN_LEVEL
    domlevel_re = re.compile(r'.*(\d)')
    if result.returncode == 0:
        # "domainlevel-get" command doesn't exist on ipa versions prior to 4.3
        level = int(domlevel_re.findall(result.stdout_text)[0])
    check_domain_level(level)
    return level


def master_authoritative_for_client_domain(master: Host, client: Host) -> bool:
    zone = ".".join(client.hostname.split('.')[1:])
    result = master.run_command(["ipa", "dnszone-show", zone],
                                raiseonerr=False)
    return result.returncode == 0


def install_replica(
    master: Host,
    replica: Host,
    setup_ca: bool = True,
    setup_dns: bool = False,
    setup_kra: bool = False,
    setup_adtrust: bool = False,
    extra_args: Iterable[str] = (),
    domain_level: Optional[int] = None,
    unattended: bool = True,
    stdin_text: Optional[str] = None,
    raiseonerr: bool = True,
    promote: bool = True,
    nameservers: Union[Literal["master"], None, str, Iterable[str]] = "master",
) -> SSHCommand:
    """
    This task installs client and then promote it to the replica

    :param nameservers: nameservers to write in resolver config. Possible
       values:
       * "master" - use ip of `master` parameter
       * None - do not setup resolver
       * IP_ADDRESS or [IP_ADDRESS, ...] - use this address as resolver

    """
    replica_args = list(extra_args)  # needed for client's ntp options
    if domain_level is None:
        domain_level = domainlevel(master)
    check_domain_level(domain_level)
    apply_common_fixes(replica)

    if "--dirsrv-config-file" not in extra_args:
        ipatests_dse: Optional[str] = prepare_dse_changes(replica)
    else:
        ipatests_dse = None

    allow_sync_ptr(master)
    fw = Firewall(replica)
    fw_services = ["freeipa-ldap", "freeipa-ldaps"]
    # Otherwise ipa-client-install would not create a PTR
    # and replica installation would fail
    args = ['ipa-replica-install',
            '--admin-password', replica.config.admin_password]

    if promote:  # while promoting we use directory manager password
        args.extend(['--password', replica.config.dirman_password])
        # install client on a replica machine and then promote it to replica
        # to configure ntp options we have to pass them to client installation
        # because promotion does not support NTP options
        ntp_args = [arg for arg in replica_args if "-ntp" in arg]

        for ntp_arg in ntp_args:
            replica_args.remove(ntp_arg)

        install_client(master, replica, extra_args=ntp_args,
                       nameservers=nameservers)
    else:
        # for one step installation of replica we need authorized user
        # to enroll a replica and master server to contact
        args.extend(['--principal', replica.config.admin_name,
                     '--server', master.hostname])
        replica.resolver.backup()
        if nameservers is not None:
            if nameservers == 'master':
                nameservers = master.ip
            replica.resolver.setup_resolver(nameservers, master.domain.name)

    if unattended:
        args.append('-U')
    if setup_ca:
        args.append('--setup-ca')
    if setup_kra:
        assert setup_ca, "CA must be installed on replica with KRA"
        args.append('--setup-kra')
    if setup_dns:
        args.extend([
            '--setup-dns',
            '--forwarder', replica.config.dns_forwarder
        ])
        fw_services.append("dns")
    if setup_adtrust:
        args.append('--setup-adtrust')
        fw_services.append("freeipa-trust")
    if master_authoritative_for_client_domain(master, replica):
        args.extend(['--ip-address', replica.ip])

    args.extend(replica_args)  # append extra arguments to installation

    fix_apache_semaphores(replica)
    args.extend(['--realm', replica.domain.realm,
                 '--domain', replica.domain.name])
    if ipatests_dse:
        args.extend(["--dirsrv-config-file", ipatests_dse])

    fw.enable_services(fw_services)

    result = replica.run_command(args, raiseonerr=raiseonerr,
                                 stdin_text=stdin_text)
    if result.returncode == 0:
        enable_ds_audit_log(replica, 'on')
        setup_sssd_conf(replica)
        kinit_admin(replica)
        if setup_dns:
            setup_named_debugging(replica)
    else:
        fw.disable_services(fw_services)
    return result


def install_client(
    master: Host,
    client: Host,
    extra_args: Iterable[str] = (),
    user: Optional[str] = None,
    password: Optional[str] = None,
    unattended: bool = True,
    stdin_text: Optional[str] = None,
    nameservers: Union[Literal["master"], None, str, Iterable[str]] = "master",
) -> SSHCommand:
    """
    :param nameservers: nameservers to write in resolver config. Possible
           values:
           * "master" - use ip of `master` parameter
           * None - do not setup resolver
           * IP_ADDRESS or [IP_ADDRESS, ...] - use this address as resolver
    """
    apply_common_fixes(client)
    allow_sync_ptr(master)
    # Now, for the situations where a client resides in a different subnet from
    # master, we need to explicitly tell master to create a reverse zone for
    # the client and enable dynamic updates for this zone.
    zone, error = prepare_reverse_zone(master, client.ip)
    if not error:
        master.run_command(["ipa", "dnszone-mod", zone,
                            "--dynamic-update=TRUE"])
    if nameservers is not None:
        client.resolver.backup()
        if nameservers == 'master':
            nameservers = master.ip
        client.resolver.setup_resolver(nameservers, master.domain.name)
    if user is None:
        user = client.config.admin_name
    if password is None:
        password = client.config.admin_password

    args = [
        'ipa-client-install',
        '--domain', client.domain.name,
        '--realm', client.domain.realm,
        '-p', user,
        '-w', password,
        '--server', master.hostname
    ]

    if unattended:
        args.append('-U')

    args.extend(extra_args)

    result = client.run_command(args, stdin_text=stdin_text)

    setup_sssd_conf(client)
    kinit_admin(client)

    return result


def install_adtrust(host: Host) -> None:
    """
    Runs ipa-adtrust-install on the client and generates SIDs for the entries.
    Configures the compat tree for the legacy clients.
    """
    kinit_admin(host)
    host.run_command(['ipa-adtrust-install', '-U',
                      '--enable-compat',
                      '--netbios-name', host.netbios,
                      '-a', host.config.admin_password,
                      '--add-sids'])

    Firewall(host).enable_service("freeipa-trust")

    # Restart named because it lost connection to dirsrv
    # (Directory server restarts during the ipa-adtrust-install)
    host.systemctl.restart("named")

    # Check that named is running and has loaded the information from LDAP
    dig_command = ['dig', 'SRV', '+short', '@localhost',
                   '_ldap._tcp.%s' % host.domain.name]
    dig_output = '0 100 389 %s.' % host.hostname
    dig_test = lambda x: bool(re.search(re.escape(dig_output), x))

    run_repeatedly(host, dig_command, test=dig_test)


def disable_dnssec_validation(host: Host) -> None:
    """
    Edits ipa-options-ext.conf snippet in order to disable dnssec validation
    """
    backup_file(host, host.ipaplatform.paths.NAMED_CUSTOM_OPTIONS_CONF)
    named_conf = host.get_file_contents(
        host.ipaplatform.paths.NAMED_CUSTOM_OPTIONS_CONF
    )
    named_conf = re.sub(br'dnssec-validation\s*yes;', b'dnssec-validation no;',
                        named_conf)
    host.put_file_contents(
        host.ipaplatform.paths.NAMED_CUSTOM_OPTIONS_CONF, named_conf
    )
    restart_named(host)


def restore_dnssec_validation(host: Host) -> None:
    restore_files(host)
    restart_named(host)


def is_subdomain(subdomain: str, domain: str) -> bool:
    subdomain_unpacked = subdomain.split('.')
    domain_unpacked = domain.split('.')

    subdomain_unpacked.reverse()
    domain_unpacked.reverse()

    issubdomain = False

    if len(subdomain_unpacked) > len(domain_unpacked):
        issubdomain = True

        for subdomain_segment, domain_segment in zip(subdomain_unpacked,
                                                     domain_unpacked):
            issubdomain = issubdomain and subdomain_segment == domain_segment

    return issubdomain


def configure_dns_for_trust(master: Host, *ad_hosts: WinHost) -> None:
    """
    This configures DNS on IPA master according to the relationship of the
    IPA's and AD's domains.
    """

    kinit_admin(master)
    dnssec_disabled = False
    for ad in ad_hosts:
        if is_subdomain(ad.domain.name, master.domain.name):
            master.run_command(['ipa', 'dnsrecord-add', master.domain.name,
                                '%s.%s' % (ad.shortname, ad.netbios),
                                '--a-ip-address', ad.ip])

            master.run_command(['ipa', 'dnsrecord-add', master.domain.name,
                                ad.netbios,
                                '--ns-hostname',
                                '%s.%s' % (ad.shortname, ad.netbios)])

            master.run_command(['ipa', 'dnszone-mod', master.domain.name,
                                '--allow-transfer', ad.ip])
        else:
            if not dnssec_disabled:
                disable_dnssec_validation(master)
                dnssec_disabled = True
            master.run_command(['ipa', 'dnsforwardzone-add', ad.domain.name,
                                '--forwarder', ad.ip,
                                '--forward-policy', 'only',
                                ])


def unconfigure_dns_for_trust(master: Host, *ad_hosts: WinHost) -> None:
    """
    This undoes changes made by configure_dns_for_trust
    """
    kinit_admin(master)
    dnssec_needs_restore = False
    for ad in ad_hosts:
        if is_subdomain(ad.domain.name, master.domain.name):
            master.run_command(['ipa', 'dnsrecord-del', master.domain.name,
                                '%s.%s' % (ad.shortname, ad.netbios),
                                '--a-rec', ad.ip])
            master.run_command(['ipa', 'dnsrecord-del', master.domain.name,
                                ad.netbios,
                                '--ns-rec',
                                '%s.%s' % (ad.shortname, ad.netbios)])
        else:
            master.run_command(['ipa', 'dnsforwardzone-del', ad.domain.name])
            dnssec_needs_restore = True
    if dnssec_needs_restore:
        restore_dnssec_validation(master)


def configure_windows_dns_for_trust(ad: WinHost, master: Host) -> None:
    ad.run_command(['dnscmd', '/zoneadd', master.domain.name,
                    '/Forwarder', master.ip])


def unconfigure_windows_dns_for_trust(ad: WinHost, master: Host) -> None:
    ad.run_command(['dnscmd', '/zonedelete', master.domain.name, '/f'])


def establish_trust_with_ad(
    master: Host,
    ad_domain: str,
    ad_admin: Optional[str] = None,
    extra_args: Iterable[str] = (),
    shared_secret: Optional[str] = None,
) -> None:
    """
    Establishes trust with Active Directory. Trust type is detected depending
    on the presence of SfU (Services for Unix) support on the AD.

    Use extra arguments to pass extra arguments to the trust-add command, such
    as --range-type="ipa-ad-trust" to enforce a particular range type.

    If ad_admin is not provided, name will be constructed as
    "Administrator@<ad_domain>".
    """

    # Force KDC to reload MS-PAC info by trying to get TGT for HTTP
    extra_args = list(extra_args)
    master.run_command(['kinit', '-kt', master.ipaplatform.paths.HTTP_KEYTAB,
                        'HTTP/%s' % master.hostname])
    master.systemctl.restart("krb5kdc")
    master.run_command(['kdestroy', '-A'])

    kinit_admin(master)
    master.run_command(['klist'])
    master.run_command(['smbcontrol', 'all', 'debug', '100'])

    if shared_secret:
        extra_args += ['--trust-secret']
        stdin_text = shared_secret
    else:
        if ad_admin is None:
            ad_admin = 'Administrator@{}'.format(ad_domain)
        extra_args += ['--admin', ad_admin, '--password']
        stdin_text = master.config.ad_admin_password
    run_repeatedly(
        master, ['ipa', 'trust-add', '--type', 'ad', ad_domain] + extra_args,
        stdin_text=stdin_text)
    master.run_command(['smbcontrol', 'all', 'debug', '1'])
    clear_sssd_cache(master)
    master.systemctl.restart("krb5kdc")
    time.sleep(60)


def remove_trust_with_ad(
    master: Host, ad_domain: str, ad_hostname: str
) -> None:
    """
    Removes trust with Active Directory. Also removes the associated ID range.
    """

    remove_trust_info_from_ad(master, ad_domain, ad_hostname)

    kinit_admin(master)

    # Remove the trust
    master.run_command(['ipa', 'trust-del', ad_domain])

    # Remove the range
    range_name = ad_domain.upper() + '_id_range'
    master.run_command(['ipa', 'idrange-del', range_name])


def remove_trust_info_from_ad(
    master: Host,
    ad_domain: str,
    ad_hostname: str,
) -> None:
    # Remove record about trust from AD
    kinit_as_user(master,
                  'Administrator@{}'.format(ad_domain.upper()),
                  master.config.ad_admin_password)
    master.run_command(['rpcclient', '-k', ad_hostname,
                        '-c', 'deletetrustdom {}'.format(master.domain.name)],
                       raiseonerr=False)


def configure_auth_to_local_rule(master: Host, ad: WinHost) -> None:
    """
    Configures auth_to_local rule in /etc/krb5.conf
    """

    section_identifier = " %s = {" % master.domain.realm
    line1 = ("  auth_to_local = RULE:[1:$1@$0](^.*@%s$)s/@%s/@%s/"
             % (ad.domain.realm, ad.domain.realm, ad.domain.name))
    line2 = "  auth_to_local = DEFAULT"

    krb5_conf_content = master.get_file_contents(
        master.ipaplatform.paths.KRB5_CONF, encoding="utf-8"
    )
    krb5_lines = [line.rstrip() for line in krb5_conf_content.split('\n')]
    realm_section_index = krb5_lines.index(section_identifier)

    krb5_lines.insert(realm_section_index + 1, line1)
    krb5_lines.insert(realm_section_index + 2, line2)

    krb5_conf_new_content = '\n'.join(krb5_lines)
    master.put_file_contents(
        master.ipaplatform.paths.KRB5_CONF,
        krb5_conf_new_content,
        encoding="utf-8",
    )

    master.systemctl.restart("sssd")


def setup_named_debugging(host: Host) -> None:
    """
    Sets debug level to debug in each section of custom logging config
    """

    host.run_command(
        [
            "sed",
            "-i",
            "s/severity info;/severity debug;/",
            host.ipaplatform.paths.NAMED_LOGGING_OPTIONS_CONF,
        ],
    )
    host.run_command(
        ["cat", host.ipaplatform.paths.NAMED_LOGGING_OPTIONS_CONF]
    )
    host.systemctl.restart("named")


def sync_time(host: Host, server: Union[Host, WinHost]) -> None:
    """
    Syncs the time with the remote server. Please note that this function
    leaves chronyd stopped.
    """

    host.systemctl.stop("chronyd")
    host.run_command(['chronyd', '-q',
                      "server {srv} iburst maxdelay 1000".format(
                          srv=server.hostname),
                      'pidfile /tmp/chronyd.pid', 'bindcmdaddress /',
                      'maxdistance 1000', 'maxjitter 1000'])


def connect_replica(
    master: Host,
    replica: Host,
    domain_level: Optional[int] = None,
    database: str = DOMAIN_SUFFIX_NAME,
) -> None:
    if domain_level is None:
        domain_level = master.config.domain_level
    check_domain_level(domain_level)
    if domain_level == DOMAIN_LEVEL_0:
        if database == DOMAIN_SUFFIX_NAME:
            cmd = 'ipa-replica-manage'
        else:
            cmd = 'ipa-csreplica-manage'
        replica.run_command([cmd, 'connect', master.hostname])
    else:
        kinit_admin(master)
        master.run_command(["ipa", "topologysegment-add", database,
                            "%s-to-%s" % (master.hostname, replica.hostname),
                            "--leftnode=%s" % master.hostname,
                            "--rightnode=%s" % replica.hostname
                            ])


def disconnect_replica(
    master: Host,
    replica: Host,
    domain_level: Optional[int] = None,
    database: str = DOMAIN_SUFFIX_NAME,
) -> None:
    if domain_level is None:
        domain_level = master.config.domain_level
    check_domain_level(domain_level)
    if domain_level == DOMAIN_LEVEL_0:
        if database == DOMAIN_SUFFIX_NAME:
            cmd = 'ipa-replica-manage'
        else:
            cmd = 'ipa-csreplica-manage'
        replica.run_command([cmd, 'disconnect', master.hostname])
    else:
        kinit_admin(master)
        master.run_command(["ipa", "topologysegment-del", database,
                            "%s-to-%s" % (master.hostname, replica.hostname),
                            "--continue"
                            ])


def kinit_user(
    host: Host, user: str, password: str, raiseonerr: bool = True
) -> SSHCommand:
    return host.run_command(['kinit', user], raiseonerr=raiseonerr,
                            stdin_text=password)


def kinit_admin(host: Host, raiseonerr: bool = True) -> SSHCommand:
    return kinit_user(host, 'admin', host.config.admin_password,
                      raiseonerr=raiseonerr)


def uninstall_master(
    host: Host,
    ignore_topology_disconnect: bool = True,
    ignore_last_of_role: bool = True,
    clean: bool = True,
    verbose: bool = False,
) -> None:
    uninstall_cmd = ['ipa-server-install', '--uninstall', '-U']

    host_domain_level = domainlevel(host)

    if ignore_topology_disconnect and host_domain_level != DOMAIN_LEVEL_0:
        uninstall_cmd.append('--ignore-topology-disconnect')

    if ignore_last_of_role and host_domain_level != DOMAIN_LEVEL_0:
        uninstall_cmd.append('--ignore-last-of-role')

    if verbose and host_domain_level != DOMAIN_LEVEL_0:
        uninstall_cmd.append('-v')

    result = host.run_command(uninstall_cmd)
    assert "Traceback" not in result.stdout_text

    # Check that IPA certs have been deleted after uninstall
    # Related: https://pagure.io/freeipa/issue/8614
    assert host.run_command(['test', '-f', host.ipaplatform.paths.IPA_CA_CRT],
                            raiseonerr=False).returncode == 1
    assert host.run_command(['test', '-f', host.ipaplatform.paths.IPA_P11_KIT],
                            raiseonerr=False).returncode == 1
    assert "IPA CA" not in host.run_command(
        ["trust", "list"], log_stdout=False
    ).stdout_text

    if clean:
        Firewall(host).disable_services(["freeipa-ldap", "freeipa-ldaps",
                                         "freeipa-trust", "dns"])

    host.run_command(['pkidestroy', '-s', 'CA', '-i', 'pki-tomcat'],
                     raiseonerr=False)
    host.run_command(
        [
            "rm",
            "-rf",
            host.ipaplatform.paths.TOMCAT_TOPLEVEL_DIR,
            host.ipaplatform.paths.SYSCONFIG_PKI_TOMCAT,
            host.ipaplatform.paths.SYSCONFIG_PKI_TOMCAT_PKI_TOMCAT_DIR,
            host.ipaplatform.paths.VAR_LIB_PKI_TOMCAT_DIR,
            host.ipaplatform.paths.PKI_TOMCAT,
            host.ipaplatform.paths.IPA_RENEWAL_LOCK,
            host.ipaplatform.paths.REPLICA_INFO_GPG_TEMPLATE % host.hostname,
        ],
        raiseonerr=False,
    )
    host.run_command(
        "find %s -name '*.keytab' | xargs rm -fv"
        % host.ipaplatform.paths.SSSD_KEYTABS_DIR,
        raiseonerr=False,
    )
    host.run_command("find /run/ipa -name 'krb5*' | xargs rm -fv",
                     raiseonerr=False)
    while host.resolver.has_backups():
        host.resolver.restore()
    if clean:
        unapply_fixes(host)


def uninstall_client(host: Host) -> None:
    host.run_command(['ipa-client-install', '--uninstall', '-U'],
                     raiseonerr=False)
    while host.resolver.has_backups():
        host.resolver.restore()
    unapply_fixes(host)


@check_arguments_are((0, 2), Host)
def clean_replication_agreement(
    master: Host,
    replica: Host,
    cleanup: bool = False,
    raiseonerr: bool = True,
) -> None:
    """
    Performs `ipa-replica-manage del replica_hostname --force`.
    """
    args = ['ipa-replica-manage', 'del', replica.hostname, '--force']
    if cleanup:
        args.append('--cleanup')
    master.run_command(args, raiseonerr=raiseonerr)


@check_arguments_are((0, 3), Host)
def create_segment(
    master: Host,
    leftnode: Host,
    rightnode: Host,
    suffix: str = DOMAIN_SUFFIX_NAME,
) -> Union[Tuple[TopoNodeDict, str], Tuple[None, str]]:
    """
    creates a topology segment. The first argument is a node to run the command
    :returns: a hash object containing segment's name, leftnode, rightnode
    information and an error string.
    """
    kinit_admin(master)
    lefthost = leftnode.hostname
    righthost = rightnode.hostname
    segment_name = "%s-to-%s" % (lefthost, righthost)
    result = master.run_command(
        ["ipa", "topologysegment-add", suffix,
         segment_name,
         "--leftnode=%s" % lefthost,
         "--rightnode=%s" % righthost],
        raiseonerr=False
    )
    if result.returncode == 0:
        segment_node: TopoNodeDict = {
            "leftnode": lefthost,
            "rightnode": righthost,
            "name": segment_name,
        }
        return segment_node, ""
    else:
        return None, result.stderr_text


def destroy_segment(
    master: Host, segment_name: str, suffix: str = DOMAIN_SUFFIX_NAME
) -> Tuple[int, str]:
    """
    Destroys topology segment.
    :param master: reference to master object of class Host
    :param segment_name: name of the segment to be created
    """
    assert isinstance(master, Host), "master should be an instance of Host"
    kinit_admin(master)
    command = ["ipa",
               "topologysegment-del",
               suffix,
               segment_name]
    result = master.run_command(command, raiseonerr=False)
    return result.returncode, result.stderr_text


def get_topo(
    name_or_func: Union[TOPO_CALLABLE_T, str]
) -> TOPO_CALLABLE_T:
    """Get a topology function by name

    A topology function receives a master and list of replicas, and yields
    (parent, child) pairs, where "child" should be installed from "parent"
    (or just connected if already installed)

    If a callable is given instead of name, it is returned directly
    """
    if callable(name_or_func):
        return name_or_func
    return topologies[name_or_func]


topologies: OrderedDict[str, TOPO_CALLABLE_T] = OrderedDict()


def _topo(name: str) -> Callable[[TOPO_WRAPPER_T], TOPO_WRAPPER_T]:
    """Decorator that registers a function in topologies under a given name"""
    def add_topo(func: TOPO_WRAPPER_T) -> TOPO_WRAPPER_T:
        topologies[name] = func
        return func
    return add_topo


@_topo('star')
def star_topo(master: Host, replicas: Iterable[Host]) -> TOPO_ITER_HOST_T:
    r"""All replicas are connected to the master

          Rn R1 R2
           \ | /
        R7-- M -- R3
           / | \
          R6 R5 R4
    """
    for replica in replicas:
        yield master, replica


@_topo('line')
def line_topo(master: Host, replicas: Iterable[Host]) -> TOPO_ITER_HOST_T:
    r"""Line topology

          M
           \
           R1
            \
            R2
             \
             R3
              \
              ...
    """
    for replica in replicas:
        yield master, replica
        master = replica


@_topo('complete')
def complete_topo(master: Host, replicas: Iterable[Host]) -> TOPO_ITER_HOST_T:
    r"""Each host connected to each other host

          M--R1
          |\/|
          |/\|
         R2-R3
    """
    for replica in replicas:
        yield master, replica
    for replica1, replica2 in itertools.combinations(replicas, 2):
        yield replica1, replica2


@_topo('tree')
def tree_topo(master: Host, replicas: Iterable[Host]) -> TOPO_ITER_HOST_T:
    r"""Binary tree topology

             M
            / \
           /   \
          R1   R2
         /  \  / \
        R3 R4 R5 R6
       /
      R7 ...

    """
    replicas = list(replicas)

    def _masters() -> Iterator[Host]:
        for host in [master] + list(replicas):
            yield host
            yield host

    for parent, child in zip(_masters(), replicas):
        yield parent, child


@_topo('tree2')
def tree2_topo(master: Host, replicas: Sequence[Host]) -> TOPO_ITER_HOST_T:
    r"""First replica connected directly to master, the rest in a line

          M
         / \
        R1 R2
            \
            R3
             \
             R4
              \
              ...

    """
    if replicas:
        yield master, replicas[0]
    for replica in replicas[1:]:
        yield master, replica
        master = replica


@_topo('2-connected')
def two_connected_topo(
    master: Host, replicas: Iterable[Host]
) -> TOPO_ITER_HOST_T:
    r"""No replica has more than 4 agreements and at least two
        replicas must fail to disconnect the topology.

         .     .     .     .
         .     .     .     .
         .     .     .     .
     ... R --- R     R --- R ...
          \   / \   / \   /
           \ /   \ /   \ /
        ... R     R     R ...
             \   / \   /
              \ /   \ /
               M0 -- R2
               |     |
               |     |
               R1 -- R3
              . \   /  .
             .   \ /    .
            .     R      .
                 .  .
                .    .
               .      .
    """
    grow = []
    pool = [master] + list(replicas)

    try:
        v0 = pool.pop(0)
        v1 = pool.pop(0)
        yield v0, v1

        v2 = pool.pop(0)
        yield v0, v2
        grow.append((v0, v2))

        v3 = pool.pop(0)
        yield v2, v3
        yield v1, v3
        grow.append((v1, v3))

        for (r, s) in grow:
            t = pool.pop(0)

            for (u, v) in [(r, t), (s, t)]:
                yield u, v
                w = pool.pop(0)
                yield u, w
                x = pool.pop(0)
                yield v, x
                yield w, x
                grow.append((w, x))

    except IndexError:
        return


@_topo('double-circle')
def double_circle_topo(
    master: Host, replicas: Iterable[Host], site_size: int = 6
) -> TOPO_ITER_HOST_T:
    r"""
                      R--R
                      |\/|
                      |/\|
                      R--R
                     /    \
                     M -- R
                    /|    |\
                   / |    | \
          R - R - R--|----|--R - R - R
          | X |   |  |    |  |   | X |
          R - R - R -|----|--R - R - R
                   \ |    | /
                    \|    |/
                     R -- R
                     \    /
                      R--R
                      |\/|
                      |/\|
                      R--R
    """
    # to provide redundancy there must be at least two replicas per site
    assert site_size >= 2
    # do not handle master other than the rest of the servers
    servers = [master] + list(replicas)

    # split servers into sites
    it = [iter(servers)] * site_size
    sites = [(x[0], x[1], x[2:]) for x in zip(*it)]
    num_sites = len(sites)

    for i in range(num_sites):
        (a, b, _ignore) = sites[i]
        # create agreement inside the site
        yield a, b

        # create agreement to one server in two next sites
        for c, _d, _ignore in [sites[(i+n) % num_sites] for n in [1, 2]]:
            yield b, c

    if site_size > 2:
        # deploy servers inside the site
        for site in sites:
            site_servers = list(site[2])
            yield site[0], site_servers[0]
            for edge in complete_topo(site_servers[0], site_servers[1:]):
                yield edge
            yield site[1], site_servers[-1]


def install_topo(
    topo: str,
    master: Host,
    replicas: Sequence[Host],
    clients: Iterable[Host],
    domain_level: Optional[int] = None,
    skip_master: bool = False,
    setup_replica_cas: bool = True,
    setup_replica_kras: bool = False,
    clients_extra_args: Iterable[str] = (),
) -> None:
    """Install IPA servers and clients in the given topology"""
    if setup_replica_kras and not setup_replica_cas:
        raise ValueError("Option 'setup_replica_kras' requires "
                         "'setup_replica_cas' set to True")
    replicas = list(replicas)
    installed = {master}
    if not skip_master:
        install_master(
            master,
            domain_level=domain_level,
            setup_kra=setup_replica_kras
        )

    add_a_records_for_hosts_in_master_domain(master)

    for parent, child in get_topo(topo)(master, replicas):
        if child in installed:
            logger.info('Connecting replica %s to %s', parent, child)
            connect_replica(parent, child)
        else:
            logger.info('Installing replica %s from %s', child, parent)
            install_replica(
                parent, child,
                setup_ca=setup_replica_cas,
                setup_kra=setup_replica_kras,
                nameservers=master.ip,
            )
        installed.add(child)
    install_clients([master] + replicas, clients, clients_extra_args)


def install_clients(
    servers: Sequence[Host],
    clients: Iterable[Host],
    extra_args: Iterable[str] = (),
    nameservers: Union[
        Literal["first", "distribute"], None, str, Iterable[str]
    ] = "first",
) -> None:
    """Install IPA clients, distributing them among the given servers

       :param nameservers: nameservers to write in resolver config on clients.
       Possible values:
       * "first" - use ip of the first item in `servers` parameter
       * "distribute" - use ip of master/replica which is used for client
                        installation
       * None - do not setup resolver
       * IP_ADDRESS or [IP_ADDRESS, ...] - use this address as resolver
    """
    izip = getattr(itertools, 'izip', zip)
    client_nameservers = nameservers
    for server, client in izip(itertools.cycle(servers), clients):
        logger.info('Installing client %s on %s', server, client)
        if nameservers == 'distribute':
            client_nameservers = server.ip
        if nameservers == 'first':
            client_nameservers = servers[0].ip
        install_client(server, client, extra_args,
                       nameservers=client_nameservers)


# TODO: replace Any with correct type on annotating LDAP
def _entries_to_ldif(entries: Any) -> str:
    """Format LDAP entries as LDIF"""
    io = StringIO()
    writer = LDIFWriter(io)
    for entry in entries:
        writer.unparse(str(entry.dn), dict(entry.raw))
    return io.getvalue()


def wait_for_replication(
    ldap: LDAPClientWithoutCertCheck,
    timeout: int = 30,
    target_status_re: str = r'^0 |^Error \(0\) ',
    raise_on_timeout: bool = False,
) -> None:
    """Wait for all replication agreements to reach desired state

    With defaults waits until updates on all replication agreements are
    done (or failed) and exits without exception
    :param ldap: LDAP client
        autenticated with necessary rights to read the mapping tree
    :param timeout: Maximum time to wait, in seconds
    :param target_status_re: Regexp of status to wait for
    :param raise_on_timeout: if True, raises AssertionError if status not
        reached in specified time

    Note that this waits for updates originating on this host, not those
    coming from other hosts.
    """
    logger.debug('Waiting for replication to finish')
    start = time.time()
    while True:
        status_attr = 'nsds5replicaLastUpdateStatus'
        progress_attr = 'nsds5replicaUpdateInProgress'
        entries = ldap.get_entries(
            DN(('cn', 'mapping tree'), ('cn', 'config')),
            filter='(objectclass=nsds5replicationagreement)',
            attrs_list=[status_attr, progress_attr])
        logger.debug('Replication agreements: \n%s', _entries_to_ldif(entries))
        statuses = [entry.single_value[status_attr] for entry in entries]
        wrong_statuses = [s for s in statuses
                          if not re.match(target_status_re, s)]
        if any(e.single_value[progress_attr] == 'TRUE' for e in entries):
            msg = 'Replication not finished'
            logger.debug(msg)
        elif wrong_statuses:
            msg = 'Unexpected replication status: %s' % wrong_statuses[0]
            logger.debug(msg)
        else:
            logger.debug('Replication finished')
            return
        if time.time() - start > timeout:
            logger.error('Giving up wait for replication to finish')
            if raise_on_timeout:
                raise AssertionError(msg)
            break
        time.sleep(1)


def wait_for_cleanallruv_tasks(
    ldap: LDAPClientWithoutCertCheck, timeout: int = 30
) -> None:
    """Wait until cleanallruv tasks are finished
    """
    logger.debug('Waiting for cleanallruv tasks to finish')
    success_status = 'Successfully cleaned rid'
    for i in range(timeout):
        status_attr = 'nstaskstatus'
        try:
            entries = ldap.get_entries(
                DN(('cn', 'cleanallruv'), ('cn', 'tasks'), ('cn', 'config')),
                scope=ldap.SCOPE_ONELEVEL,
                attrs_list=[status_attr])
        except errors.EmptyResult:
            logger.debug("No cleanallruv tasks")
            break
        # Check status
        if all(
            e.single_value[status_attr].startswith(success_status)
            for e in entries
        ):
            logger.debug("All cleanallruv tasks finished successfully")
            break
        logger.debug("cleanallruv task in progress, (waited %s/%ss)",
                     i, timeout)
        time.sleep(1)
    else:
        logger.error('Giving up waiting for cleanallruv to finish')
        for e in entries:
            stat_str = e.single_value[status_attr]
            if not stat_str.startswith(success_status):
                logger.debug('%s status: %s', e.dn, stat_str)


def add_a_records_for_hosts_in_master_domain(master: Host) -> None:
    for host in master.domain.hosts:
        # We don't need to take care of the zone creation since it is master
        # domain
        assert isinstance(host, Host)
        add_a_record(master, host)


def add_a_record(master: Host, host: Host) -> None:
    # Find out if the record is already there
    cmd = master.run_command(['ipa',
                              'dnsrecord-show',
                              master.domain.name,
                              host.hostname + "."],
                             raiseonerr=False)

    # If not, add it
    if cmd.returncode != 0:
        master.run_command(['ipa',
                            'dnsrecord-add',
                            master.domain.name,
                            host.hostname + ".",
                            '--a-rec', host.ip])


def resolve_record(
    nameserver: str,
    query: str,
    rtype: Union[int, str] = "SOA",
    retry: bool = True,
    timeout: int = 100,
) -> Any:
    """Resolve DNS record
    :retry: if resolution failed try again until timeout is reached
    :timeout: max period of time while method will try to resolve query
     (requires retry=True)
    """
    res = DNSResolver()
    res.nameservers = [nameserver]
    res.lifetime = 10  # wait max 10 seconds for reply

    wait_until = time.time() + timeout

    while time.time() < wait_until:
        try:
            ans = res.resolve(query, rtype)
            return ans
        except dns.exception.DNSException:
            if not retry:
                raise
        time.sleep(1)


def ipa_backup(
    host: Host, disable_role_check: bool = False, raiseonerr: bool = True
) -> SSHCommand:
    """Run backup on host and return the run_command result.
    """
    cmd = ['ipa-backup', '-v']
    if disable_role_check:
        cmd.append('--disable-role-check')
    result = host.run_command(cmd, raiseonerr=raiseonerr)

    # Test for ticket 7632: check that services are restarted
    # before the backup is compressed
    pattern = r'.*{}.*Starting IPA service.*'.format(
        host.ipaplatform.paths.GZIP
    )
    if (re.match(pattern, result.stderr_text, re.DOTALL)):
        raise AssertionError('IPA Services are started after compression')

    return result


def ipa_epn(
    host: Host,
    dry_run: bool = False,
    from_nbdays: Union[int, str, None] = None,
    to_nbdays: Union[int, str, None] = None,
    raiseonerr: bool = True,
    mailtest: bool = False,
) -> SSHCommand:
    """Run EPN on host and return the run_command result.
    """
    cmd = ["ipa-epn"]
    if dry_run:
        cmd.append("--dry-run")
    if mailtest:
        cmd.append("--mail-test")
    if from_nbdays is not None:
        cmd.extend(("--from-nbdays", str(from_nbdays)))
    if to_nbdays is not None:
        cmd.extend(("--to-nbdays", str(to_nbdays)))
    return host.run_command(cmd, raiseonerr=raiseonerr)


@overload
def get_backup_dir(host: Host, raiseonerr: Literal[True] = True) -> str:
    ...


@overload
def get_backup_dir(
    host: Host, raiseonerr: Literal[False]
) -> Optional[str]:
    ...


@overload
def get_backup_dir(host: Host, raiseonerr: bool = True) -> Optional[str]:
    ...


def get_backup_dir(host: Host, raiseonerr: bool = True) -> Optional[str]:
    """Wrapper around ipa_backup: returns the backup directory.
    """
    result = ipa_backup(host, raiseonerr)

    # Get the backup location from the command's output
    for line in result.stderr_text.splitlines():
        prefix = 'ipaserver.install.ipa_backup: INFO: Backed up to '
        if line.startswith(prefix):
            backup_path = line[len(prefix):].strip()
            logger.info('Backup path for %s is %s', host.hostname, backup_path)
            return backup_path
    else:
        if raiseonerr:
            raise AssertionError('Backup directory not found in output')
        else:
            return None


def ipa_restore(master: Host, backup_path: str) -> None:
    master.run_command(["ipa-restore", "-U",
                        "-p", master.config.dirman_password,
                        backup_path])


def install_kra(
    host: Host,
    domain_level: Optional[int] = None,
    raiseonerr: bool = True,
) -> SSHCommand:
    if domain_level is None:
        domain_level = domainlevel(host)
    check_domain_level(domain_level)
    command = ["ipa-kra-install", "-U", "-p", host.config.dirman_password]
    result = host.run_command(command, raiseonerr=raiseonerr)
    return result


def install_ca(
    host: Host,
    domain_level: Optional[int] = None,
    external_ca: bool = False,
    cert_files: Optional[Iterable[str]] = None,
    raiseonerr: bool = True,
    extra_args: Iterable[str] = (),
) -> SSHCommand:
    if domain_level is None:
        domain_level = domainlevel(host)
    check_domain_level(domain_level)
    command = ["ipa-ca-install", "-U", "-p", host.config.dirman_password,
               "-P", 'admin', "-w", host.config.admin_password]
    if not isinstance(extra_args, (tuple, list)):
        raise TypeError("extra_args must be tuple or list")
    command.extend(extra_args)
    # First step of ipa-ca-install --external-ca
    if external_ca:
        command.append('--external-ca')
    # Continue with ipa-ca-install --external-ca
    if cert_files:
        for fname in cert_files:
            command.extend(['--external-cert-file', fname])
    result = host.run_command(command, raiseonerr=raiseonerr)
    return result


def install_dns(
    host: Host,
    raiseonerr: bool = True,
    extra_args: Iterable[str] = (),
) -> SSHCommand:
    args = [
        "ipa-dns-install",
        "--forwarder", host.config.dns_forwarder,
        "-U",
    ]
    args.extend(extra_args)
    ret = host.run_command(args, raiseonerr=raiseonerr)
    Firewall(host).enable_service("dns")
    return ret


def uninstall_replica(master: Host, replica: Host) -> None:
    master.run_command(["ipa-replica-manage", "del", "--force",
                        "-p", master.config.dirman_password,
                        replica.hostname], raiseonerr=False)
    uninstall_master(replica)


def replicas_cleanup(
    func: Callable[..., Any]
) -> Callable[..., Any]:
    """
    replicas_cleanup decorator, applied to any test method in integration tests
    uninstalls all replicas in the topology leaving only master
    configured
    """
    def wrapped(self: IntegrationTest_T, *args: Any) -> None:
        func(self, *args)
        for host in self.replicas:
            uninstall_replica(self.master, host)
            uninstall_client(host)
            result = self.master.run_command(
                ["ipa", "host-del", "--updatedns", host.hostname],
                raiseonerr=False,
            )
            # Workaround for 5627
            if "host not found" in result.stderr_text:
                self.master.run_command(
                    ["ipa", "host-del", host.hostname], raiseonerr=False
                )
    return wrapped


def run_server_del(
    host: Host,
    server_to_delete: str,
    force: bool = False,
    ignore_topology_disconnect: bool = False,
    ignore_last_of_role: bool = False,
) -> SSHCommand:
    kinit_admin(host)
    args = ['ipa', 'server-del', server_to_delete]
    if force:
        args.append('--force')
    if ignore_topology_disconnect:
        args.append('--ignore-topology-disconnect')
    if ignore_last_of_role:
        args.append('--ignore-last-of-role')

    return host.run_command(args, raiseonerr=False)


def run_certutil(
    host: Host,
    args: Iterable[str],
    reqdir: str,
    dbtype: Optional[str] = None,
    stdin: Optional[str] = None,
    raiseonerr: bool = True,
) -> SSHCommand:
    dbdir = reqdir if dbtype is None else '{}:{}'.format(dbtype, reqdir)
    new_args = [host.ipaplatform.paths.CERTUTIL, '-d', dbdir]
    new_args.extend(args)
    return host.run_command(new_args, raiseonerr=raiseonerr,
                            stdin_text=stdin)


def certutil_certs_keys(
    host: Host,
    reqdir: str,
    pwd_file: str,
    token_name: Optional[str] = None,
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Run certutils and get mappings of cert and key files
    """
    base_args = ['-f', pwd_file]
    if token_name is not None:
        base_args.extend(['-h', token_name])
    cert_args = base_args + ['-L']
    key_args = base_args + ['-K']

    result = run_certutil(host, cert_args, reqdir)
    certs: Dict[str, str] = {}
    for line in result.stdout_text.splitlines():
        mo = certdb.CERT_RE.match(line)
        if mo:
            certs[mo.group('nick')] = mo.group('flags')

    result = run_certutil(host, key_args, reqdir)
    assert 'orphan' not in result.stdout_text
    keys: Dict[str, str] = {}
    for line in result.stdout_text.splitlines():
        mo = certdb.KEY_RE.match(line)
        if mo:
            keys[mo.group('nick')] = mo.group('keyid')
    return certs, keys


def certutil_fetch_cert(
    host: Host,
    reqdir: str,
    pwd_file: str,
    nickname: str,
    token_name: Optional[str] = None,
) -> Certificate:
    """Run certutil and retrieve a cert as cryptography.x509 object
    """
    args = ['-f', pwd_file, '-L', '-a', '-n']
    if token_name is not None:
        args.extend([
            '{}:{}'.format(token_name, nickname),
            '-h', token_name
        ])
    else:
        args.append(nickname)
    result = run_certutil(host, args, reqdir)
    return x509.load_pem_x509_certificate(
        result.stdout_bytes, default_backend()
    )


def upload_temp_contents(
    host: Host,
    contents: Union[str, bytes],
    encoding: Optional[str] = "utf-8",
) -> str:
    """Upload contents to a temporary file

    :param host: Remote host instance
    :param contents: file content (str, bytes)
    :param encoding: file encoding
    :return: Temporary file name
    """
    result = host.run_command(['mktemp'])
    tmpname = result.stdout_text.strip()
    host.put_file_contents(tmpname, contents, encoding=encoding)
    return tmpname


def assert_error(
    result: SSHCommand,
    pattern: Union[str, Pattern[str]],
    returncode: Optional[int] = None,
) -> None:
    """
    Assert that ``result`` command failed and its stderr contains ``pattern``.
    ``pattern`` may be a ``str`` or a ``re.Pattern`` (regular expression).

    """
    if isinstance(pattern, re.Pattern):
        assert pattern.search(result.stderr_text), \
            f"pattern {pattern} not found in stderr {result.stderr_text!r}"
    else:
        assert pattern in result.stderr_text, \
            f"substring {pattern!r} not found in stderr {result.stderr_text!r}"

    if returncode is not None:
        assert result.returncode == returncode
    else:
        assert result.returncode > 0


def restart_named(*args: Host) -> None:
    time.sleep(20)  # give a time to DNSSEC daemons to provide keys for named
    for host in args:
        host.systemctl.restart("named")
    time.sleep(20)  # give a time to named to be ready (zone loading)


def run_repeatedly(
    host: Host,
    command: SSHCOMMAND_ARGV_TYPE,
    assert_zero_rc: bool = True,
    test: Optional[Callable[[str], bool]] = None,
    timeout: int = 30,
    **kwargs: Any,
) -> bool:
    """
    Runs command on host repeatedly until it's finished successfully (returns
    0 exit code and its stdout passes the test function).

    Returns True if the command was executed succesfully, False otherwise.

    This method accepts additional kwargs and passes these arguments
    to the actual run_command method.
    """

    time_waited = 0
    time_step = 2

    # Check that the test is a function
    if test:
        assert callable(test)

    while(time_waited <= timeout):
        result = host.run_command(command, raiseonerr=False, **kwargs)

        return_code_ok = not assert_zero_rc or (result.returncode == 0)
        test_ok = not test or test(result.stdout_text)

        if return_code_ok and test_ok:
            # Command successful
            return True
        else:
            # Command not successful
            time.sleep(time_step)
            time_waited += time_step

    raise AssertionError("Command: {cmd} repeatedly failed {times} times, "
                         "exceeding the timeout of {timeout} seconds."
                         .format(cmd=command,
                                 times=timeout // time_step,
                                 timeout=timeout))


def get_host_ip_with_hostmask(host: Host) -> Optional[str]:
    """Detects the IP of the host including the hostmask

    Returns None if the IP could not be detected.
    """
    ip = host.ip
    result = host.run_command(['ip', 'addr'])
    full_ip_regex = r'(?P<full_ip>%s/\d{1,2}) ' % re.escape(ip)
    match = re.search(full_ip_regex, result.stdout_text)

    if match:
        return match.group('full_ip')
    else:
        return None


def ldappasswd_user_change(
    user: str,
    oldpw: str,
    newpw: str,
    master: Host,
    use_dirman: bool = False,
    raiseonerr: bool = True,
) -> SSHCommand:
    container_user = dict(DEFAULT_CONFIG)['container_user']
    basedn = master.domain.basedn

    userdn = "uid={},{},{}".format(user, container_user, basedn)
    master_ldap_uri = "ldap://{}".format(master.hostname)

    if use_dirman:
        args = [master.ipaplatform.paths.LDAPPASSWD, '-D',
                str(master.config.dirman_dn),  # pylint: disable=no-member
                '-w', master.config.dirman_password,
                '-s', newpw, '-x', '-ZZ', '-H', master_ldap_uri, userdn]
    else:
        args = [master.ipaplatform.paths.LDAPPASSWD, '-D',
                userdn, '-w', oldpw, '-a', oldpw,
                '-s', newpw, '-x', '-ZZ', '-H', master_ldap_uri]
    return master.run_command(args, raiseonerr=raiseonerr)


def ldappasswd_sysaccount_change(
    user: str, oldpw: str, newpw: str, master: Host, use_dirman: bool = False
) -> None:
    container_sysaccounts = dict(DEFAULT_CONFIG)['container_sysaccounts']
    basedn = master.domain.basedn

    userdn = "uid={},{},{}".format(user, container_sysaccounts, basedn)
    master_ldap_uri = "ldap://{}".format(master.hostname)

    if use_dirman:
        args = [master.ipaplatform.paths.LDAPPASSWD, '-D',
                str(master.config.dirman_dn),  # pylint: disable=no-member
                '-w', master.config.dirman_password,
                '-a', oldpw,
                '-s', newpw, '-x', '-ZZ', '-H', master_ldap_uri,
                userdn]
    else:
        args = [master.ipaplatform.paths.LDAPPASSWD, '-D',
                userdn, '-w', oldpw, '-a', oldpw,
                '-s', newpw, '-x', '-ZZ', '-H', master_ldap_uri]
    master.run_command(args)


def add_dns_zone(
    master: Host,
    zone: str,
    skip_overlap_check: bool = False,
    dynamic_update: bool = False,
    add_a_record_hosts: Optional[Iterable[Host]] = None,
) -> None:
    """
    Add DNS zone if it is not already added.
    """

    result = master.run_command(
        ['ipa', 'dnszone-show', zone], raiseonerr=False)

    if result.returncode != 0:
        command = ['ipa', 'dnszone-add', zone]
        if skip_overlap_check:
            command.append('--skip-overlap-check')
        if dynamic_update:
            command.append('--dynamic-update=True')

        master.run_command(command)

        if add_a_record_hosts:
            for host in add_a_record_hosts:
                master.run_command(['ipa', 'dnsrecord-add', zone,
                                    host.hostname + ".", '--a-rec', host.ip])
    else:
        logger.debug('Zone %s already added.', zone)


def sign_ca_and_transport(
    host: Host,
    csr_name: str,
    root_ca_name: str,
    ipa_ca_name: str,
    root_ca_path_length: Optional[int] = None,
    ipa_ca_path_length: Optional[int] = 1,
    key_size: Optional[int] = None,
    root_ca_extensions: Iterable[ExtensionType] = (),
) -> Tuple[str, str]:
    """
    Sign ipa csr and save signed CA together with root CA back to the host.
    Returns root CA and IPA CA paths on the host.
    """

    test_dir = host.config.test_dir

    # Get IPA CSR as bytes
    ipa_csr = host.get_file_contents(csr_name)

    external_ca = ExternalCA(key_size=key_size)
    # Create root CA
    root_ca = external_ca.create_ca(
        path_length=root_ca_path_length,
        extensions=root_ca_extensions,
    )
    # Sign CSR
    ipa_ca = external_ca.sign_csr(ipa_csr, path_length=ipa_ca_path_length)

    root_ca_fname = os.path.join(test_dir, root_ca_name)
    ipa_ca_fname = os.path.join(test_dir, ipa_ca_name)

    # Transport certificates (string > file) to master
    host.put_file_contents(root_ca_fname, root_ca)
    host.put_file_contents(ipa_ca_fname, ipa_ca)

    return root_ca_fname, ipa_ca_fname


def generate_ssh_keypair() -> Tuple[str, str]:
    """
    Create SSH keypair for key authentication testing
    """
    key = rsa.generate_private_key(backend=default_backend(),
                                   public_exponent=65537,
                                   key_size=2048)

    public_key = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        # paramiko does not support PKCS#8 format, yet.
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    private_key_str = pem.decode('utf-8')
    public_key_str = public_key.decode('utf-8')

    return (private_key_str, public_key_str)


def strip_cert_header(pem: str) -> str:
    """
    Remove the header and footer from a certificate.
    """
    regexp = (
        r"^-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----"
    )
    s = re.search(regexp, pem, re.MULTILINE | re.DOTALL)
    if s is not None:
        return s.group(1)
    else:
        return pem


def user_add(
    host: Host,
    login: str,
    first: str = "test",
    last: str = "user",
    extra_args: Iterable[str] = (),
    password: Optional[str] = None,
) -> SSHCommand:
    cmd = [
        "ipa", "user-add", login,
        "--first", first,
        "--last", last
    ]
    if password is not None:
        cmd.append('--password')
        stdin_text: Optional[str] = '{0}\n{0}\n'.format(password)
    else:
        stdin_text = None
    cmd.extend(extra_args)
    return host.run_command(cmd, stdin_text=stdin_text)


def user_del(host: Host, login: str) -> SSHCommand:
    cmd = ["ipa", "user-del", login]
    return host.run_command(cmd)


def group_add(
    host: Host, groupname: str, extra_args: Iterable[str] = ()
) -> SSHCommand:
    cmd = [
        "ipa", "group-add", groupname,
    ]
    cmd.extend(extra_args)
    return host.run_command(cmd)


def ldapmodify_dm(host: Host, ldif_text: str, **kwargs: Any) -> SSHCommand:
    """Run ldapmodify as Directory Manager

    :param host: host object
    :param ldif_text: ldif string
    :param kwargs: additional keyword arguments to run_command()
    :return: result object
    """
    # no hard-coded hostname, let ldapmodify pick up the host from ldap.conf.
    args = [
        'ldapmodify',
        '-x',
        '-D', str(host.config.dirman_dn),
        '-w', host.config.dirman_password
    ]
    return host.run_command(args, stdin_text=ldif_text, **kwargs)


def ldapsearch_dm(
    host: Host,
    base: str,
    ldap_args: Iterable[str],
    scope: str = "sub",
    **kwargs: Any,
) -> SSHCommand:
    """Run ldapsearch as Directory Manager

    :param host: host object
    :param base: Base DN
    :param ldap_args: additional arguments to ldapsearch (filter, attributes)
    :param scope: search scope (base, sub, one)
    :param kwargs: additional keyword arguments to run_command()
    :return: result object
    """
    args = [
        'ldapsearch',
        '-x', '-ZZ',
        '-h', host.hostname,
        '-p', '389',
        '-D', str(host.config.dirman_dn),
        '-w', host.config.dirman_password,
        '-s', scope,
        '-b', base,
        '-o', 'ldif-wrap=no',
        '-LLL',
    ]
    args.extend(ldap_args)
    return host.run_command(args, **kwargs)


def create_active_user(
    host: Host,
    login: str,
    password: str,
    first: str = "test",
    last: str = "user",
    extra_args: Iterable[str] = (),
    krb5_trace: bool = False,
) -> None:
    """Create user and do login to set password"""
    temp_password = 'Secret456789'
    kinit_admin(host)
    user_add(host, login, first=first, last=last, extra_args=extra_args,
             password=temp_password)
    if krb5_trace:
        # Retrieve kdcinfo.$REALM before changing the user's password.
        get_kdcinfo(host)
        # This tends to fail when the KDC the password is
        # reset on is not the same as the one we immediately
        # request a TGT from. This should not be the case as SSSD
        # tries to pin itself to an IPA server.
        #
        # Note raiseonerr=False:
        # the assert is located after kdcinfo retrieval.
        result = host.run_command(
            "KRB5_TRACE=/dev/stdout kinit %s" % login,
            stdin_text='{0}\n{1}\n{1}\n'.format(temp_password, password),
            raiseonerr=False,
        )
        # Retrieve kdc.$REALM after the password change, just in case SSSD
        # domain status flipped to online during the password change.
        get_kdcinfo(host)
        assert result.returncode == 0
    else:
        host.run_command(
            ['kinit', login],
            stdin_text='{0}\n{1}\n{1}\n'.format(temp_password, password)
        )
    kdestroy_all(host)


def kdestroy_all(host: Host) -> SSHCommand:
    return host.run_command(['kdestroy', '-A'])


def run_command_as_user(
    host: Host,
    user: str,
    command: Union[str, Iterable[str]],
    *args: Any,
    **kwargs: Any,
) -> SSHCommand:
    """Run command on remote host using 'su -l'

    Arguments are similar to Host.run_command
    """
    if not isinstance(command, str):
        command = ' '.join(quote(s) for s in command)
    cwd = kwargs.pop('cwd', None)
    if cwd is not None:
        command = 'cd {}; {}'.format(quote(cwd), command)
    command = ['su', '-l', user, '-c', command]
    return host.run_command(command, *args, **kwargs)


def kinit_as_user(
    host: Host,
    user: str,
    password: str,
    krb5_trace: bool = False,
    raiseonerr: bool = True,
) -> SSHCommand:
    """Launch kinit as user on host.
    If krb5_trace, then set KRB5_TRACE=/dev/stdout and collect
    /var/lib/sss/pubconf/kdcinfo.$REALM
    as this file contains the list of KRB5KDC IPs SSSD uses.
    https://pagure.io/freeipa/issue/8510
    """

    if krb5_trace:
        # Retrieve kdcinfo.$REALM before changing the user's password.
        get_kdcinfo(host)
        # This tends to fail when the KDC the password is
        # reset on is not the same as the one we immediately
        # request a TGT from. This should not be the case as SSSD
        # tries to pin itself to an IPA server.
        #
        # Note raiseonerr=False:
        # the assert is located after kdcinfo retrieval.
        result = host.run_command(
            "KRB5_TRACE=/dev/stdout kinit %s" % user,
            stdin_text='{0}\n'.format(password),
            raiseonerr=False
        )
        # Retrieve kdc.$REALM after the password change, just in case SSSD
        # domain status flipped to online during the password change.
        get_kdcinfo(host)
        if raiseonerr:
            assert result.returncode == 0
        return result
    else:
        return host.run_command(
            ['kinit', user],
            stdin_text='{0}\n'.format(password),
            raiseonerr=raiseonerr)


def get_kdcinfo(host: Host) -> Optional[bytes]:
    """Retrieve /var/lib/sss/pubconf/kdcinfo.$REALM on host.
    That file contains the IP of the KDC SSSD should be pinned to.
    """
    logger.info(
        'Collecting kdcinfo log from: %s', host.hostname
    )
    if check_if_sssd_is_online(host):
        logger.info("SSSD considers domain %s online.", host.domain.realm)
    else:
        logger.warning(
            "SSSD considers domain %s offline.", host.domain.realm
        )
    kdcinfo = None
    try:
        kdcinfo = host.get_file_contents(
            "/var/lib/sss/pubconf/kdcinfo.{}".format(host.domain.realm)
        )
        logger.info(
            'kdcinfo %s contains:\n%s', host.hostname, kdcinfo
        )
        if check_if_sssd_is_online(host) is False:
            logger.warning(
                "SSSD still considers domain %s offline.",
                host.domain.realm
            )
    except (OSError, IOError) as e:
        logger.warning(
            "Exception collecting kdcinfo.%s: %s\n"
            "SSSD is able to function without this file but logon "
            "attempts immediately after a password change might break.",
            host.domain.realm, e
        )
    return kdcinfo


class KeyEntry(NamedTuple):
    kvno: str
    principal: str
    etype: str
    key: str


class KerberosKeyCopier:
    """Copy Kerberos keys from a keytab to a keytab on a target host

    Example:
       Copy host/master1.ipa.test principal as MASTER$ in a temporary keytab

       # host - master1.ipa.test
       copier = KerberosKeyCopier(host)
       realm = host.domain.realm
       principal = copier.host_princ_template.format(
           master=host.hostname, realm=realm)
       replacement = {principal: f'MASTER$@{realm}'}

       result = host.run_command(['mktemp'])
       tmpname = result.stdout_text.strip()

       copier.copy_keys('/etc/krb5.keytab', tmpname, replacement=replacement)
    """
    host_princ_template = "host/{master}@{realm}"
    valid_etypes = ['aes256-cts-hmac-sha1-96', 'aes128-cts-hmac-sha1-96']

    def __init__(self, host: Host) -> None:
        self.host = host
        self.realm = host.domain.realm

    def extract_key_refs(
        self, keytab: str, princ: Optional[str] = None
    ) -> List[KeyEntry]:
        if princ is None:
            princ = self.host_princ_template.format(master=self.host.hostname,
                                                    realm=self.realm)
        result = self.host.run_command(
            [self.host.ipaplatform.paths.KLIST, "-eK", "-k", keytab],
            log_stdout=False,
        )

        keys_to_sync = []
        for l in result.stdout_text.splitlines():
            if (princ in l and any(e in l for e in self.valid_etypes)):

                els = l.split()
                els[-2] = els[-2].strip('()')
                els[-1] = els[-1].strip('()')
                keys_to_sync.append(KeyEntry._make(els))

        return keys_to_sync

    def copy_key(self, keytab: str, keyentry: KeyEntry) -> None:
        def get_keytab_mtime() -> Optional[str]:
            """Get keytab file mtime.

            Returns mtime with sub-second precision as a string with format
            "2020-08-25 14:35:05.980503425 +0200" or None if file does not
            exist.
            """
            if self.host.transport.file_exists(keytab):
                return self.host.run_command(
                    ['stat', '-c', '%y', keytab]).stdout_text.strip()
            return None

        mtime_before = get_keytab_mtime()

        with self.host.spawn_expect(
            self.host.ipaplatform.paths.KTUTIL,
            default_timeout=5,
            extra_ssh_options=['-t'],
        ) as e:
            e.expect_exact('ktutil:')
            e.sendline('rkt {}'.format(keytab))
            e.expect_exact('ktutil:')
            e.sendline(
                'addent -key -p {principal} -k {kvno} -e {etype}'
                .format(principal=keyentry.principal, kvno=keyentry.kvno,
                        etype=keyentry.etype,))
            e.expect('Key for.+:')
            # keyentry.key is a hex value of the actual key
            # prefixed with 0x, as produced by klist -K -k.
            # However, ktutil accepts hex value without 0x, so
            # we should strip first two characters.
            e.sendline(keyentry.key[2:])
            e.expect_exact('ktutil:')
            e.sendline('wkt {}'.format(keytab))
            e.expect_exact('ktutil:')
            e.sendline('q')

        if mtime_before == get_keytab_mtime():
            raise Exception(
                '{} did not update keytab file "{}"'.format(
                    self.host.ipaplatform.paths.KTUTIL, keytab
                )
            )

    def copy_keys(
        self,
        origin: str,
        destination: str,
        principal: Optional[str] = None,
        replacement: Mapping[str, str] = {},
    ) -> None:
        def sync_keys(
            origkeys: Iterable[KeyEntry], destkeys: Iterable[KeyEntry]
        ) -> None:
            for origkey in origkeys:
                copied = False
                uptodate = False
                if origkey.principal in replacement:
                    origkey = origkey._replace(
                        principal=replacement[origkey.principal]
                    )
                for destkey in destkeys:
                    if all([destkey.principal == origkey.principal,
                            destkey.etype == origkey.etype]):
                        if any([destkey.key != origkey.key,
                                destkey.kvno != origkey.kvno]):
                            self.copy_key(destination, origkey)
                            copied = True
                            break
                        uptodate = True
                if not (copied or uptodate):
                    self.copy_key(destination, origkey)

        if not self.host.transport.file_exists(origin):
            raise ValueError('File "{}" does not exist'.format(origin))
        origkeys = self.extract_key_refs(origin, princ=principal)
        if self.host.transport.file_exists(destination):
            destkeys = self.extract_key_refs(destination)
            if any([origkeys is None, destkeys is None]):
                raise Exception(
                    'Either {} or {} are missing or unreadable'.format(
                        origin, destination))
            sync_keys(origkeys, destkeys)
        else:
            for origkey in origkeys:
                if origkey.principal in replacement:
                    newkey = KeyEntry._make(
                        [origkey.kvno, replacement.get(origkey.principal),
                         origkey.etype, origkey.key])
                    origkey = newkey
                self.copy_key(destination, origkey)


class FileBackup:
    """Create file backup and do restore on remote host

    Examples:

        config_backup = FileBackup(host, '/etc/some.conf')
        ... modify the file and do the test ...
        config_backup.restore()

    Use as a context manager:

        with FileBackup(host, '/etc/some.conf'):
            ... modify the file and do the test ...

    """

    def __init__(self, host: Host, filename: str) -> None:
        """Create file backup."""
        self._host = host
        self._filename = filename
        self._backup = create_temp_file(host)
        host.run_command(['cp', '--preserve=all', filename, self._backup])

    def restore(self) -> None:
        """Restore file. Can be called only once."""
        self._host.run_command(['mv', self._backup, self._filename])

    def __enter__(self) -> FileBackup:
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.restore()


@contextmanager
def remote_ini_file(host: Host, filename: str) -> Iterator[RawConfigParser]:
    """Context manager for editing an ini file on a remote host.

    It provides RawConfigParser object which is automatically serialized and
    uploaded to remote host upon exit from the context.

    If exception is raised inside the context then the ini file is NOT updated
    on remote host.

    Example:

        with remote_ini_file(master, '/etc/some.conf') as some_conf:
            some_conf.set('main', 'timeout', 10)


    """
    data = host.get_file_contents(filename, encoding='utf-8')
    ini_file = configparser.RawConfigParser()
    ini_file.read_string(data)
    yield ini_file
    data_io = StringIO()
    ini_file.write(data_io)
    host.put_file_contents(filename, data_io.getvalue())


def get_logsize(host: Host, logfile: str) -> int:
    """ get current logsize"""
    logsize = len(host.get_file_contents(logfile))
    return logsize


def install_packages(host: Host, pkgs: Iterable[str]) -> None:
    """Install packages on a remote host.
    :param host: the host where the installation takes place
    :param pkgs: packages to install, provided as a list of strings
    """
    platform = host.ipaplatform.osinfo.platform
    if platform in ('rhel', 'fedora'):
        install_cmd = ['/usr/bin/dnf', 'install', '-y']
    elif platform in ('ubuntu'):
        install_cmd = ['apt-get', 'install', '-y']
    else:
        raise ValueError('install_packages: unknown platform %s' % platform)
    install_cmd.extend(pkgs)
    host.run_command(install_cmd)


def download_packages(host: Host, pkgs: Iterable[str]) -> str:
    """Download packages on a remote host.
    :param host: the host where the download takes place
    :param pkgs: packages to install, provided as a list of strings

    A package can't be downloaded that is already installed.

    Returns the temporary directory where the packages are.
    The caller is responsible for cleanup.
    """
    platform = host.ipaplatform.osinfo.platform
    tmpdir = os.path.join('/tmp', str(uuid.uuid4()))
    # Only supports RHEL 8+ and Fedora for now
    if platform in ('rhel', 'fedora'):
        install_cmd = ['/usr/bin/dnf', '-y',
                       '--downloaddir', tmpdir,
                       '--downloadonly',
                       'install']
    else:
        raise ValueError('install_packages: unknown platform %s' % platform)
    host.run_command(['mkdir', tmpdir])
    install_cmd.extend(pkgs)
    host.run_command(install_cmd)
    return tmpdir


def uninstall_packages(
    host: Host, pkgs: Iterable[str], nodeps: bool = False
) -> None:
    """Uninstall packages on a remote host.
    :param host: the host where the uninstallation takes place.
    :param pkgs: packages to uninstall, provided as a list of strings.
    :param nodeps: ignore dependencies (dangerous!).
    """
    platform = host.ipaplatform.osinfo.platform
    if platform not in ('rhel', 'fedora', 'ubuntu'):
        raise ValueError('uninstall_packages: unknown platform %s' % platform)
    if nodeps:
        if platform in ('rhel', 'fedora'):
            cmd = "rpm -e --nodeps"
        elif platform in ('ubuntu'):
            cmd = "dpkg -P --force-depends"
        for package in pkgs:
            uninstall_cmd = shlex.split(cmd)
            uninstall_cmd.append(package)
            # keep raiseonerr=True here. --fcami
            host.run_command(uninstall_cmd)
    else:
        if platform in ('rhel', 'fedora'):
            cmd = "/usr/bin/dnf remove -y"
        elif platform in ('ubuntu'):
            cmd = "apt-get remove -y"
        uninstall_cmd = shlex.split(cmd)
        uninstall_cmd.extend(pkgs)
        host.run_command(uninstall_cmd, raiseonerr=False)


def wait_for_request(host: Host, request_id: str, timeout: int = 120) -> str:
    for _i in range(0, timeout, 5):
        result = host.run_command(
            "getcert list -i %s | grep status: | awk '{ print $2 }'" %
            request_id
        )

        state = result.stdout_text.strip()
        logger.info("certmonger request is in state %s", state)
        if state in ('CA_REJECTED', 'CA_UNREACHABLE', 'CA_UNCONFIGURED',
                     'NEED_GUIDANCE', 'NEED_CA', 'MONITORING'):
            break
        time.sleep(5)
    else:
        raise RuntimeError("request timed out")

    return state


def wait_for_certmonger_status(
    host: Host, status: Iterable[str], request_id: str, timeout: int = 120
) -> str:
    """Aggressively wait for a specific certmonger status.

       This checks the status every second in order to attempt to
       catch transient states like SUBMITTED. There are no guarantees.

       :param host: the host where the uninstallation takes place
       :param status: tuple of statuses to look for
       :param request_id: request_id of request to check status on
       :param timeout: max time in seconds to wait for the status
    """
    for _i in range(0, timeout, 1):
        result = host.run_command(
            "getcert list -i %s | grep status: | awk '{ print $2 }'" %
            request_id
        )

        state = result.stdout_text.strip()
        logger.info("certmonger request is in state %s", state)
        if state in status:
            break
        time.sleep(1)
    else:
        raise RuntimeError("request timed out")

    return state


def get_pki_version(host: Host) -> Version:
    """Get pki version on remote host."""
    data = host.get_file_contents("/usr/share/pki/VERSION", encoding="utf-8")

    groups = re.match(r'.*\nSpecification-Version: ([\d+\.]*)\n.*', data)
    if groups:
        version_string = groups.group(1)
        return parse_version(version_string)
    else:
        raise ValueError("get_pki_version: pki is not installed")


def get_healthcheck_version(host: Host) -> str:
    """
    Function to get healthcheck version on fedora and rhel
    """
    platform = host.ipaplatform.osinfo.platform
    if platform in ("rhel", "fedora"):
        cmd = host.run_command(
            ["rpm", "-qa", "--qf", "%{VERSION}", "*ipa-healthcheck"]
        )
        healthcheck_version = cmd.stdout_text
        if not healthcheck_version:
            raise ValueError(
                "get_healthcheck_version: "
                "ipa-healthcheck package is not installed"
            )
    else:
        raise ValueError(
            "get_healthcheck_version: unknown platform %s" % platform
        )
    return healthcheck_version


def wait_for_ipa_to_start(host: Host, timeout: int = 60) -> None:
    """Wait up to timeout seconds for ipa to start on a given host.

    If DS is restarted, and SSSD must be online, please consider using
    wait_for_sssd_domain_status_online(host) in the test after calling
    this method.
    """
    interval = 1
    end_time = datetime.now() + timedelta(seconds=timeout)
    for _i in range(0, timeout, interval):
        if datetime.now() > end_time:
            raise RuntimeError("Request timed out")
        time.sleep(interval)
        result = host.run_command(
            [host.ipaplatform.paths.IPACTL, "status"], raiseonerr=False
        )
        if result.returncode == 0:
            break


def dns_update_system_records(host: Host) -> None:
    """Runs "ipa dns-update-system-records" on "host".
    """
    kinit_admin(host)
    host.run_command(
        ["ipa", "dns-update-system-records"]
    )


def run_ssh_cmd(
    to_host: str,
    username: str,
    auth_method: str,
    cmd: str = "true",
    password: Optional[str] = None,
    private_key_path: Optional[str] = None,
    expect_auth_success: bool = True,
    expect_auth_failure: Optional[bool] = None,
    verbose: bool = True,
    connect_timeout: int = 2,
    strict_host_key_checking: bool = False,
) -> Tuple[int, str, str]:
    """Runs an ssh connection from the controller to the host.
       - auth_method can be either "password" or "key".
       - In the first case, set password to the user's password ; in the
         second case, set private_key_path to the path of the private key.
       - If expect_auth_success or expect_auth_failure, analyze the ssh
         client's log and check whether the selected authentication method
         worked. expect_auth_failure takes precedence over expect_auth_success.
       - If verbose, display the ssh client verbose log.
       - Both expect_auth_success and verbose are True by default. Debugging
         ssh client failures is next to impossible without the associated
         debug log.
       Possible enhancements:
       - select which host to run from (currently: controller only)
    """

    if expect_auth_failure:
        expect_auth_success = False

    if auth_method == "password":
        if password is None:
            raise ValueError(
                "password is mandatory if auth_method == password"
            )
        ssh_cmd = [
            "ssh",
            "-v",
            "-o", "PubkeyAuthentication=no",
            "-o", "GSSAPIAuthentication=no",
            "-o", "ConnectTimeout={connect_timeout}".format(
                connect_timeout=connect_timeout
            ),
        ]
    elif auth_method == "key":
        if private_key_path is None:
            raise ValueError(
                "private_key_path is mandatory if auth_method == key"
            )
        ssh_cmd = [
            "ssh",
            "-v",
            "-o", "BatchMode=yes",
            "-o", "PubkeyAuthentication=yes",
            "-o", "GSSAPIAuthentication=no",
            "-o", "ConnectTimeout={connect_timeout}".format(
                connect_timeout=connect_timeout
            ),
        ]
    else:
        raise ValueError(
            "auth_method must either be password or key"
        )

    ssh_cmd_1 = ssh_cmd
    if strict_host_key_checking is True:
        ssh_cmd_1.extend(("-o", "StrictHostKeyChecking=yes"))
    else:
        ssh_cmd_1.extend(("-o", "StrictHostKeyChecking=no"))
    if auth_method == "password":
        assert password is not None  # cast out Optional mypy#645
        ssh_cmd_1 = list(("sshpass", "-p", password)) + ssh_cmd_1
    elif auth_method == "key":
        assert private_key_path is not None  # cast out Optional mypy#645
        ssh_cmd_1.extend(("-i", private_key_path))
    ssh_cmd_1.extend(("-l", username, to_host, cmd))

    try:
        if verbose:
            output = "OpenSSH command: {sshcmd}".format(sshcmd=ssh_cmd_1)
            logger.info(output)
        remote_cmd = subprocess.Popen(
            ssh_cmd_1,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        while remote_cmd.poll() is None:
            time.sleep(0.1)
        return_code = remote_cmd.returncode

        if remote_cmd.stderr is None:
            raise RuntimeError("stderr was not captured")

        if remote_cmd.stdout is None:
            raise RuntimeError("stdout was not captured")

        stderr = os.linesep.join(
            str(line) for line in remote_cmd.stderr.readlines()
        )
        stdout = os.linesep.join(
            str(line) for line in remote_cmd.stdout.readlines()
        )
        if verbose:
            print_stdout = "Standard output: {stdout}".format(stdout=stdout)
            print_stderr = "Standard error: {stderr}".format(stderr=stderr)
            logger.info(print_stdout)
            logger.info(print_stderr)
    except Exception:
        # pytest by default reports the traceback
        pytest.fail("Unable to run ssh command.")

    if auth_method == "password":
        if expect_auth_success is True:
            assert "Authentication succeeded (keyboard-interactive)" in \
                stderr
            # do not assert the return code:
            # it can be >0 if the command failed.
        elif expect_auth_failure is True:
            # sshpass return code: 5 for failed auth
            assert return_code == 5
            assert "Authentication succeeded" not in stderr
    elif auth_method == "key":
        if expect_auth_success is True:
            assert "Authentication succeeded (publickey)" in stderr
            # do not assert the return code:
            # it can be >0 if the command failed.
        elif expect_auth_failure is True:
            # ssh return code: 255 for failed auth
            assert return_code == 255
            assert "Authentication succeeded" not in stderr
            assert "No more authentication methods to try." in stderr
    return (return_code, stdout, stderr)


def is_package_installed(host: Host, pkg: str) -> bool:
    platform = host.ipaplatform.osinfo.platform
    if platform in ('rhel', 'fedora'):
        result = host.run_command(
            ['rpm', '-q', pkg], raiseonerr=False
        )
    elif platform in ['ubuntu']:
        result = host.run_command(
            ['dpkg', '-s', pkg], raiseonerr=False
        )
    else:
        raise ValueError(
            'is_package_installed: unknown platform %s' % platform
        )
    return result.returncode == 0
