# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2011  Red Hat
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

"""Pytest plugin for IPA Integration tests"""

from __future__ import annotations

from pprint import pformat

import logging
import os
import tempfile
import shutil
import re

import pytest
from pytest_multihost import make_multihost_fixture

from ipapython import ipautil
from .config import Config
from .env_config import get_global_config
from . import tasks

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import (
        Any,
        Iterable,
        Iterator,
        List,
        Optional,
        Sequence,
        Type,
    )

    from _pytest.fixtures import FixtureRequest
    from _pytest.config import Config as PytestConfig
    from _pytest.config.argparsing import Parser
    from _pytest.nodes import Node
    # currently exists only in stub file
    # pylint: disable=no-name-in-module
    from pytest_multihost.config import DomainDescriptionDict
    # pylint: enable=no-name-in-module
    from pytest_multihost.plugin import MultihostFixture
    from .config import Domain
    from .host import Host, WinHost
    from ipatests.pytest_ipa.integration._types import (
        HOST_LOGS_RTYPE, HOST_LOGS_ATYPE, IpaMHFixture
    )
    from ipatests.test_integration.base import IntegrationTest


logger = logging.getLogger(__name__)


def make_class_logs(host: Host) -> List[str]:
    host_constants = host.ipaplatform.constants
    host_paths = host.ipaplatform.paths
    logs = [
        # BIND logs
        os.path.join(host_paths.NAMED_VAR_DIR, host_constants.NAMED_DATA_DIR),
        # dirsrv logs
        host_paths.VAR_LOG_DIRSRV,
        # IPA install logs
        host_paths.IPASERVER_INSTALL_LOG,
        host_paths.IPASERVER_ADTRUST_INSTALL_LOG,
        host_paths.IPASERVER_DNS_INSTALL_LOG,
        host_paths.IPASERVER_KRA_INSTALL_LOG,
        host_paths.IPACLIENT_INSTALL_LOG,
        host_paths.IPAREPLICA_INSTALL_LOG,
        host_paths.IPAREPLICA_CONNCHECK_LOG,
        host_paths.IPAREPLICA_CA_INSTALL_LOG,
        host_paths.IPA_CUSTODIA_AUDIT_LOG,
        host_paths.IPACLIENTSAMBA_INSTALL_LOG,
        host_paths.IPACLIENTSAMBA_UNINSTALL_LOG,
        host_paths.IPATRUSTENABLEAGENT_LOG,
        # IPA uninstall logs
        host_paths.IPASERVER_UNINSTALL_LOG,
        host_paths.IPACLIENT_UNINSTALL_LOG,
        # IPA upgrade logs
        host_paths.IPAUPGRADE_LOG,
        # IPA backup and restore logs
        host_paths.IPARESTORE_LOG,
        host_paths.IPABACKUP_LOG,
        # EPN log
        host_paths.IPAEPN_LOG,
        # kerberos related logs
        host_paths.KADMIND_LOG,
        host_paths.KRB5KDC_LOG,
        # httpd logs
        host_paths.VAR_LOG_HTTPD_DIR,
        # dogtag logs
        host_paths.VAR_LOG_PKI_DIR,
        # dogtag conf
        host_paths.PKI_TOMCAT_SERVER_XML,
        os.path.join(host_paths.PKI_TOMCAT, "ca", "CS.cfg"),
        os.path.join(host_paths.PKI_TOMCAT, "kra", "CS.cfg"),
        host_paths.PKI_TOMCAT_ALIAS_DIR,
        host_paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT,
        # selinux logs
        host_paths.VAR_LOG_AUDIT,
        # sssd
        host_paths.VAR_LOG_SSSD_DIR,
        # system
        host_paths.RESOLV_CONF,
        host_paths.HOSTS,
        # IPA renewal lock
        host_paths.IPA_RENEWAL_LOCK,
        host_paths.LETS_ENCRYPT_LOG,
        # resolvers management
        host_paths.NETWORK_MANAGER_CONFIG,
        host_paths.NETWORK_MANAGER_CONFIG_DIR,
        host_paths.SYSTEMD_RESOLVED_CONF,
        host_paths.SYSTEMD_RESOLVED_CONF_DIR,
    ]
    env_filename = os.path.join(host.config.test_dir, 'env.sh')
    logs.append(env_filename)
    return logs


def pytest_addoption(parser: Parser) -> None:
    group = parser.getgroup("IPA integration tests")

    group.addoption(
        '--logfile-dir', dest="logfile_dir", default=None,
        help="Directory to store integration test logs in.")


def _get_logname_from_node(node: Node) -> str:
    name = node.nodeid
    name = re.sub(r'\(\)/', '', name)      # remove ()/
    name = re.sub(r'[()]', '', name)       # and standalone brackets
    name = re.sub(r'(/|::)', '-', name)
    return name


def collect_test_logs(
    node: Node,
    logs_dict: HOST_LOGS_ATYPE,
    test_config: PytestConfig,
    suffix: str = "",
) -> None:
    """Collect logs from a test

    Calls collect_logs and collect_systemd_journal

    :param node: The pytest collection node (request.node)
    :param logs_dict: Mapping of host to list of log filnames to collect
    :param test_config: Pytest configuration
    :param suffix: The custom suffix of the name of logfiles' directory
    """
    name = '{node}{suffix}'.format(
        node=_get_logname_from_node(node),
        suffix=suffix,
    )
    logfile_dir: Optional[str] = test_config.getoption('logfile_dir')
    collect_logs(
        name=name,
        logs_dict=logs_dict,
        logfile_dir=logfile_dir,
        beakerlib_plugin=test_config.pluginmanager.getplugin('BeakerLibPlugin'),
    )

    hosts = logs_dict.keys()  # pylint: disable=dict-keys-not-iterating
    collect_systemd_journal(name, hosts, logfile_dir)


def collect_systemd_journal(
    name: str, hosts: Iterable[Host], logfile_dir: Optional[str] = None
) -> None:
    """Collect systemd journal from remote hosts

    :param name: Name under which logs are collected, e.g. name of the test
    :param hosts: List of hosts from which to collect journal
    :param logfile_dir: Directory to log to
    """
    if logfile_dir is None:
        return

    for host in hosts:
        logger.info("Collecting journal from: %s", host.hostname)

        topdirname = os.path.join(logfile_dir, name, host.hostname)
        if not os.path.exists(topdirname):
            os.makedirs(topdirname)

        # Get journal content
        cmd = host.run_command(
            ['journalctl', '--since', host.config.log_journal_since],
            log_stdout=False, raiseonerr=False)
        if cmd.returncode:
            logger.error('An error occurred while collecting journal')
            continue

        # Write journal to file
        with open(os.path.join(topdirname, "journal"), 'w') as f:
            f.write(cmd.stdout_text)


def collect_logs(
    name: str,
    logs_dict: HOST_LOGS_ATYPE,
    logfile_dir: Optional[str] = None,
    beakerlib_plugin: Any = None,  # not annotated yet
) -> None:
    """Collect logs from remote hosts

    Calls collect_logs

    :param name: Name under which logs arecollected, e.g. name of the test
    :param logs_dict: Mapping of host to list of log filnames to collect
    :param logfile_dir: Directory to log to
    :param beakerlib_plugin:
        BeakerLibProcess or BeakerLibPlugin used to collect tests for BeakerLib

    If neither logfile_dir nor beakerlib_plugin is given, no tests are
    collected.
    """
    if logs_dict and (logfile_dir or beakerlib_plugin):

        if logfile_dir:
            remove_dir = False
        else:
            logfile_dir = tempfile.mkdtemp()
            remove_dir = True

        topdirname = os.path.join(logfile_dir, name)

        for host, logs in logs_dict.items():
            logger.info('Collecting logs from: %s', host.hostname)
            # make list of unique log filenames
            logs = list(set(logs))
            dirname = os.path.join(topdirname, host.hostname)
            if not os.path.isdir(dirname):
                os.makedirs(dirname)
            tarname = os.path.join(dirname, 'logs.tar.xz')
            # get temporary file name
            cmd = host.run_command(['mktemp'])
            tmpname = cmd.stdout_text.strip()
            # Tar up the logs on the remote server
            cmd = host.run_command(
                [
                    "tar",
                    "cJvf",
                    tmpname,
                    "--ignore-failed-read",
                    "--warning=no-failed-read",
                    "--dereference",
                ] + logs,
                log_stdout=False,
                raiseonerr=False,
            )
            if cmd.returncode:
                logger.warning('Could not collect all requested logs')
            # fetch tar file
            with open(tarname, 'wb') as f:
                f.write(host.get_file_contents(tmpname))
            # delete from remote
            host.run_command(['rm', '-f', tmpname])
            # Unpack on the local side
            ipautil.run(["tar", 'xJvf', 'logs.tar.xz'], cwd=dirname,
                        raiseonerr=False)
            os.unlink(tarname)

        if beakerlib_plugin:
            # Use BeakerLib's rlFileSubmit on the indifidual files
            # The resulting submitted filename will be
            # $HOSTNAME-$FILENAME (with '/' replaced by '-')
            beakerlib_plugin.run_beakerlib_command(['pushd', topdirname])
            try:
                for dirpath, _dirnames, filenames in os.walk(topdirname):
                    for filename in filenames:
                        fullname = os.path.relpath(
                            os.path.join(dirpath, filename), topdirname)
                        logger.debug('Submitting file: %s', fullname)
                        beakerlib_plugin.run_beakerlib_command(
                            ['rlFileSubmit', fullname])
            finally:
                beakerlib_plugin.run_beakerlib_command(['popd'])

        if remove_dir:
            if beakerlib_plugin:
                # The BeakerLib process runs asynchronously, let it clean up
                # after it's done with the directory
                beakerlib_plugin.run_beakerlib_command(
                    ['rm', '-rvf', topdirname])
            else:
                shutil.rmtree(topdirname)


class IntegrationLogs:
    """Represent logfile collections
    Collection is a mapping of IPA hosts and a list of logfiles to be
    collected. There are two types of collections: class and method.
    The former contains a list of logfiles which will be collected on
    each test (within class) completion, while the latter contains
    a list of logfiles which will be collected on only certain test
    completion (once).
    """
    def __init__(self) -> None:
        self._class_logs: HOST_LOGS_RTYPE = {}
        self._method_logs: HOST_LOGS_RTYPE = {}

    def set_logs(self, host: Host, logs: Sequence[str]) -> None:
        self._class_logs[host] = list(logs)

    @property
    def method_logs(self) -> HOST_LOGS_RTYPE:
        return self._method_logs

    @property
    def class_logs(self) -> HOST_LOGS_RTYPE:
        return self._class_logs

    def init_method_logs(self) -> None:
        """Initilize method logs with the class ones"""
        self._method_logs = {}
        for k in self._class_logs:
            self._method_logs[k] = list(self._class_logs[k])

    def collect_class_log(self, host: Host, filename: str) -> None:
        """Add class scope log
        The file with the given filename will be collected from the
        host on an each test completion(within a test class).
        """
        logger.info('Adding %s:%s to list of class logs to collect',
                    host.external_hostname, filename)
        self._class_logs.setdefault(host, []).append(filename)
        self._method_logs.setdefault(host, []).append(filename)

    def collect_method_log(self, host: Host, filename: str) -> None:
        """Add method scope log
        The file with the given filename will be collected from the
        host on a test completion.
        """
        logger.info('Adding %s:%s to list of method logs to collect',
                    host.external_hostname, filename)
        self._method_logs.setdefault(host, []).append(filename)


@pytest.fixture(scope='class')
def class_integration_logs(
    request: FixtureRequest
) -> Iterator[IntegrationLogs]:
    """Internal fixture providing class-level logs_dict
    For adjusting collection of logs, please, use 'integration_logs'
    fixture.
    """
    integration_logs = IntegrationLogs()
    yield integration_logs
    # since the main fixture of integration tests('mh') depends on
    # this one the class logs collecting happens *after* the teardown
    # of that fixture. The 'uninstall' is among the finalizers of 'mh'.
    # This means that the logs collected here are the IPA *uninstall*
    # logs.
    class_logs = integration_logs.class_logs
    collect_test_logs(request.node, class_logs, request.config,
                      suffix='-uninstall')


@pytest.fixture
def integration_logs(
    class_integration_logs: IntegrationLogs, request: FixtureRequest
) -> Iterator[IntegrationLogs]:
    """Provides access to test integration logs, and collects after each test
    To collect a logfile on a test completion one should add the dependency on
    this fixture and call its 'collect_method_log' method.
    For example, run TestFoo.
    ```
    class TestFoo(IntegrationTest):
        def test_foo(self):
            pass

        def test_bar(self, integration_logs):
            integration_logs.collect_method_log(self.master, '/logfile')
    ```
    '/logfile' will be collected only for 'test_bar' test.

    To collect a logfile on a test class completion one should add the
    dependency on this fixture and call its 'collect_class_log' method.
    For example, run TestFoo.
    ```
    class TestFoo(IntegrationTest):
        def test_foo(self, integration_logs):
            integration_logs.collect_class_log(self.master, '/logfile')

        def test_bar(self):
            pass
    ```
    '/logfile' will be collected 3 times:
    1) on 'test_foo' completion
    2) on 'test_bar' completion
    3) on 'TestFoo' completion

    Note, the registration of a collection works at the runtime. This means
    that if the '/logfile' will be registered in 'test_bar' then
    it will not be collected on 'test_foo' completion:
    1) on 'test_bar' completion
    2) on 'TestFoo' completion
    """
    class_integration_logs.init_method_logs()
    yield class_integration_logs
    method_logs = class_integration_logs.method_logs
    collect_test_logs(request.node, method_logs, request.config)


def process_hostmarkers(request: FixtureRequest) -> None:
    for mark in request.node.iter_markers():
        if mark.name in [
            "skip_if_hostplatform",
            "skip_if_hostcontainer",
            "skip_if_hostfips",
            "skip_if_not_hostselinux",
            "skip_if_host",
        ]:
            # not all deps are available on pypi
            from .host import Host

            hostattr = mark.kwargs.get("host")
            if hostattr is None:
                hostattr = mark.args[0]

            if not isinstance(hostattr, str):
                raise TypeError(
                    f"hostattr should be str, given: {hostattr!r}"
                )

            hosts = getattr(request.cls, hostattr)
            hostindex = mark.kwargs.get("hostindex")
            if hostindex is not None:
                host = hosts[int(hostindex)]
            else:
                host = hosts
            if not isinstance(host, Host):
                raise TypeError(f"Supported only IPA hosts, given: {host!r}")

            reason = mark.kwargs["reason"]
            if not isinstance(reason, str):
                raise TypeError(f"Reason should be str, given: {reason!r}")

            if mark.name == "skip_if_hostplatform":
                platform = mark.kwargs["platform"]
                if platform in host.ipaplatform.osinfo.platform_ids:
                    pytest.skip(
                        f"{request.node.nodeid}: Skip test on remote host "
                        f"'{host.hostname}' running on platform '{platform}': "
                        f"{reason}"
                    )
            if mark.name == "skip_if_hostcontainer":
                container = mark.kwargs["container"]
                if not isinstance(container, str):
                    raise TypeError(
                        f"container should be str, given: {container!r}"
                    )
                if container in ["any", host.ipaplatform.osinfo.container]:
                    pytest.skip(
                        f"{request.node.nodeid}: Skip test on remote host "
                        f"'{host.hostname}' running in container '{container}'"
                        f": {reason}"
                    )
            if mark.name == "skip_if_hostfips":
                if host.is_fips_mode:
                    pytest.skip(
                        f"{request.node.nodeid}: Skip test on remote host "
                        f"'{host.hostname}' running in FIPS mode: {reason}"
                    )
            if mark.name == "skip_if_not_hostselinux":
                if not host.is_selinux_enabled:
                    pytest.skip(
                        f"{request.node.nodeid}: Skip test on remote host "
                        f"'{host.hostname}' not running in SELinux mode: "
                        f"{reason}"
                    )
            if mark.name == "skip_if_host":
                condition_cb = mark.kwargs["condition_cb"]
                if not callable(condition_cb):
                    raise TypeError("condition_cb should be callable")

                if condition_cb(host):
                    pytest.skip(
                        f"{request.node.nodeid}: Skip test on remote host "
                        f"'{host.hostname}': {reason}"
                    )

@pytest.fixture(scope='class')
def mh(
    request: FixtureRequest, class_integration_logs: IntegrationLogs
) -> Iterator[IpaMHFixture]:
    """IPA's multihost fixture object
    """
    # actually can be any class
    cls: Type[IntegrationTest] = request.cls

    domain_description: DomainDescriptionDict = {
        'type': 'IPA',
        'hosts': {
            'master': 1,
            'replica': cls.num_replicas,
            'client': cls.num_clients,
        },
    }
    domain_description['hosts'].update(
        {role: 1 for role in cls.required_extra_roles})

    domain_descriptions = [domain_description]
    for _i in range(cls.num_ad_domains):
        domain_descriptions.append({
            'type': 'AD',
            'hosts': {'ad': 1}
        })
    for _i in range(cls.num_ad_subdomains):
        domain_descriptions.append({
            'type': 'AD_SUBDOMAIN',
            'hosts': {'ad_subdomain': 1}
        })
    for _i in range(cls.num_ad_treedomains):
        domain_descriptions.append({
            'type': 'AD_TREEDOMAIN',
            'hosts': {'ad_treedomain': 1}
        })

    # for typing dynamically added attrs, is not safe
    mh: IpaMHFixture = make_multihost_fixture(  # type: ignore[assignment]
        request,
        domain_descriptions,
        config_class=Config,
        _config=get_global_config(),
    )

    # these MultihostFixture attrs added dynamically
    mh.domain = mh.config.domains[0]
    [mh.master] = mh.domain.hosts_by_role('master')
    mh.replicas = mh.domain.hosts_by_role('replica')
    mh.clients = mh.domain.hosts_by_role('client')
    ad_domains = mh.config.ad_domains
    if ad_domains:
        mh.ads = []
        for domain in ad_domains:
            mh.ads.extend(domain.hosts_by_role('ad'))
        mh.ad_subdomains = []
        for domain in ad_domains:
            mh.ad_subdomains.extend(domain.hosts_by_role('ad_subdomain'))
        mh.ad_treedomains = []
        for domain in ad_domains:
            mh.ad_treedomains.extend(domain.hosts_by_role('ad_treedomain'))

    add_compat_attrs(cls, mh)

    # handle pytest marks which perform host checks *before* install
    process_hostmarkers(request)

    cls.logs_to_collect = class_integration_logs.class_logs

    if logger.isEnabledFor(logging.INFO):
        logger.info(pformat(mh.config.to_dict()))

    for ipa_host in mh.config.get_all_ipa_hosts():
        class_integration_logs.set_logs(ipa_host, make_class_logs(ipa_host))

    for host in mh.config.get_all_hosts():
        logger.info('Preparing host %s', host.hostname)
        tasks.prepare_host(host)

    def fin() -> None:
        del_compat_attrs(cls)
    mh._pytestmh_request.addfinalizer(fin)

    try:
        yield mh.install()
    finally:
        # the 'mh' fixture depends on 'class_integration_logs' one,
        # thus, the class logs collecting happens *after* the teardown
        # of 'mh' fixture. The 'uninstall' is among the finalizers of 'mh'.
        # This means that the logs collected here are the IPA *uninstall*
        # logs and the 'install' ones can be removed during the IPA
        # uninstall phase. To address this problem(e.g. installation error)
        # the install logs will be collected into '{nodeid}-install' directory
        # while the uninstall ones into '{nodeid}-uninstall'.
        class_logs = class_integration_logs.class_logs
        collect_test_logs(request.node, class_logs, request.config,
                          suffix='-install')


def add_compat_attrs(cls: Type[IntegrationTest], mh: IpaMHFixture) -> None:
    """Add convenience attributes to the test class

    This is deprecated in favor of the mh fixture.
    To be removed when no more tests using this.
    """
    cls.domain = mh.domain
    cls.master = mh.master
    cls.replicas = list(mh.replicas)
    cls.clients = list(mh.clients)
    cls.ad_domains = mh.config.ad_domains
    if cls.ad_domains:
        cls.ads = list(mh.ads)
        cls.ad_subdomains = mh.ad_subdomains
        cls.ad_treedomains = mh.ad_treedomains


def del_compat_attrs(cls: Type[IntegrationTest]) -> None:
    """Remove convenience attributes from the test class

    This is deprecated in favor of the mh fixture.
    To be removed when no more tests using this.
    """
    del cls.master
    del cls.replicas
    del cls.clients
    del cls.domain
    if cls.ad_domains:
        del cls.ads
        del cls.ad_subdomains
        del cls.ad_treedomains
    del cls.ad_domains
