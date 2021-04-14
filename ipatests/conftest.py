#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
from __future__ import annotations

import os
import pprint
import shutil
import sys
import tempfile

import pytest

from ipalib import api
from ipalib.cli import cli_plugins
import ipatests.util

try:
    import ipaplatform  # pylint: disable=unused-import
    from ipaplatform.osinfo import osinfo
except ImportError:
    ipaplatform = None  # type: ignore[assignment] # mypy#1153
    osinfo = None  # type: ignore[assignment] # mypy#1153

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from _pytest.config import Config
    from _pytest.config.argparsing import Parser
    from _pytest.fixtures import FixtureRequest
    from _pytest.nodes import Item


HERE = os.path.dirname(os.path.abspath(__file__))


class PytestIPADeprecationWarning(pytest.PytestWarning, DeprecationWarning):
    """Warning class for features that will be removed in a future version."""

pytest_plugins = [
    'ipatests.pytest_ipa.additional_config',
    'ipatests.pytest_ipa.deprecated_frameworks',
    'ipatests.pytest_ipa.slicing',
    'ipatests.pytest_ipa.beakerlib',
    'ipatests.pytest_ipa.declarative',
    'ipatests.pytest_ipa.nose_compat',
    'ipatests.pytest_ipa.integration',
    'pytester',
]


MARKERS = [
    'tier0: basic unit tests and critical functionality',
    'tier1: functional API tests',
    'cs_acceptance: Acceptance test suite for Dogtag Certificate Server',
    'ds_acceptance: Acceptance test suite for 389 Directory Server',
    'skip_ipaclient_unittest: Skip in ipaclient unittest mode',
    'needs_ipaapi: Test needs IPA API',
    ('skip_if_platform(platform, reason): Skip test on platform '
     '(ID and ID_LIKE)'),
    ('skip_if_container(type, reason): Skip test on container '
     '("any" or specific type)'),
    (
        "skip_if_hostplatform(host's attribute name within IntegrationTest "
        "(for example, 'master', 'clients', 'replicas'), "
        "index of host within hosts list if required(default: None), "
        "platform name, reason): "
        "Skip integration test on remote platform having ID or ID_LIKE"
    ),
    (
        "skip_if_hostcontainer(host's attribute name within IntegrationTest "
        "(for example, 'master', 'clients', 'replicas'), "
        "index of host within hosts list if required(default: None), "
        "container type, reason): "
        "Skip integration test on remote container ('any' or specific type)"
    ),
    (
        "skip_if_hostfips(host's attribute name within IntegrationTest "
        "(for example, 'master', 'clients', 'replicas'), "
        "index of host within hosts list if required(default: None), "
        "reason): Skip integration test on remote host in FIPS mode"
    ),
    (
        "skip_if_host(host's attribute name within IntegrationTest "
        "(for example, 'master', 'clients', 'replicas'), "
        "index of host within hosts list if required(default: None), "
        "condition callback, reason): "
        "Skip integration test on remote host based on condition callback "
        "result"
    ),
    (
        "skip_if_not_hostselinux(host's attribute name within IntegrationTest "
        "(for example, 'master', 'clients', 'replicas'), "
        "index of host within hosts list if required(default: None), "
        "reason): Skip integration test on remote host not at SELinux mode"
    ),
]


NO_RECURSE_DIRS = [
    # build directories
    'ipaclient/build',
    'ipalib/build',
    'ipaplatform/build',
    'ipapython/build',
    'ipaserver/build',
    'ipatests/build',
    # install/share/wsgi.py
    'install/share',
    # integration plugin imports from ipaplatform
    'ipatests/pytest_ipa',
    'ipatests/azure',
]


INIVALUES = {
    'python_classes': ['test_', 'Test'],
    'python_files': ['test_*.py'],
    'python_functions': ['test_*'],
}


def pytest_configure(config: Config) -> None:
    # add pytest markers
    for marker in MARKERS:
        config.addinivalue_line('markers', marker)

    # do not recurse into build directories or install/share directory.
    for norecursedir in NO_RECURSE_DIRS:
        config.addinivalue_line('norecursedirs', norecursedir)

    # addinivalue_line() adds duplicated entries and does not remove existing.
    for name, values in INIVALUES.items():
        current = config.getini(name)
        current[:] = values

    # set default JUnit prefix
    if config.option.junitprefix is None:
        config.option.junitprefix = 'ipa'

    # always run doc tests
    config.option.doctestmodules = True

    # apply global options
    ipatests.util.SKIP_IPAAPI = config.option.skip_ipaapi
    ipatests.util.IPACLIENT_UNITTESTS = config.option.ipaclient_unittests
    ipatests.util.PRETTY_PRINT = config.option.pretty_print


def pytest_addoption(parser: Parser) -> None:
    group = parser.getgroup("IPA integration tests")
    group.addoption(
        '--ipaclient-unittests',
        help='Run ipaclient unit tests only (no RPC and ipaserver)',
        action='store_true'
    )
    group.addoption(
        '--skip-ipaapi',
        help='Do not run tests that depends on IPA API',
        action='store_true',
    )


def pytest_cmdline_main(config: Config) -> None:
    kwargs = dict(
        context=u'cli', in_server=False, fallback=False
    )
    # FIXME: workaround for https://pagure.io/freeipa/issue/8317
    kwargs.update(in_tree=True)
    if not os.path.isfile(os.path.expanduser('~/.ipa/default.conf')):
        # dummy domain/host for machines without ~/.ipa/default.conf
        kwargs.update(domain=u'ipa.test', server=u'master.ipa.test')

    api.bootstrap(**kwargs)
    for klass in cli_plugins:
        api.add_plugin(klass)

    # XXX workaround until https://fedorahosted.org/freeipa/ticket/6408 has
    # been resolved.
    if os.path.isfile(api.env.conf_default):
        api.finalize()

    if config.option.verbose:
        print('api.env: ')
        pprint.pprint({k: api.env[k] for k in api.env})
        print("uname: {}".format(os.uname()))
        print("euid: {}, egid: {}".format(os.geteuid(), os.getegid()))
        print("working dir: {}".format(os.path.abspath(os.getcwd())))
        print('sys.version: {}'.format(sys.version))


def pytest_runtest_setup(item: Item) -> None:
    if isinstance(item, pytest.Function):
        if item.get_closest_marker('skip_ipaclient_unittest'):
            # pylint: disable=no-member
            if item.config.option.ipaclient_unittests:
                pytest.skip("Skip in ipaclient unittest mode")
        if item.get_closest_marker('needs_ipaapi'):
            # pylint: disable=no-member
            if item.config.option.skip_ipaapi:
                pytest.skip("Skip tests that needs an IPA API")
    if osinfo is not None:
        tests_dir = item.nodeid.split(os.sep, 1)[0]
        for mark in item.iter_markers(name="skip_if_platform"):
            if tests_dir == "test_integration":
                raise ValueError(
                    f"Marker '{mark.name}' is not intended for "
                    f"test_integration. Please, consider host markers:\n"
                    "ipa-run-tests --markers"
                )
            platform = mark.kwargs.get("platform")
            if platform is None:
                platform = mark.args[0]
            reason = mark.kwargs["reason"]
            if platform in osinfo.platform_ids:
                pytest.skip(f"Skip test on platform {platform}: {reason}")
        for mark in item.iter_markers(name="skip_if_container"):
            if tests_dir == "test_integration":
                raise ValueError(
                    f"Marker '{mark.name}' is not intended for "
                    f"test_integration. Please, consider host markers:\n"
                    "ipa-run-tests --markers"
                )
            container = mark.kwargs.get("container")
            if container is None:
                container = mark.args[0]
            reason = mark.kwargs["reason"]
            if osinfo.container is not None:
                if container in ('any', osinfo.container):
                    pytest.skip(
                        f"Skip test on '{container}' container type: {reason}")


def pytest_runtest_call(item: Item) -> None:
    # process only own_markers to avoid double checking
    # all the host markers have been handled in mh fixture before this hook
    for mark in item.own_markers:
        if mark.name in [
            "skip_if_hostplatform",
            "skip_if_hostcontainer",
            "skip_if_hostfips",
            "skip_if_not_hostselinux",
            "skip_if_host",
        ]:
            # not all deps are available on pypi
            from ipatests.pytest_ipa.integration.host import Host

            tests_dir = item.nodeid.split(os.sep, 1)[0]
            if tests_dir != "test_integration":
                raise ValueError(
                    f"Marker '{mark.name}' is intended only for "
                    f"test_integration and can't be applied for '{tests_dir}'"
                )
            hostattr = mark.kwargs.get("host")
            if hostattr is None:
                hostattr = mark.args[0]

            if not isinstance(hostattr, str):
                raise TypeError(
                    f"hostattr should be str, given: {hostattr!r}"
                )

            hosts = getattr(item.cls, hostattr)  # type: ignore[attr-defined]
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
                        f"{item.nodeid}: Skip test on remote host "
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
                        f"{item.nodeid}: Skip test on remote host "
                        f"'{host.hostname}' running in container '{container}'"
                        f": {reason}"
                    )

            if mark.name == "skip_if_hostfips":
                if host.is_fips_mode:
                    pytest.skip(
                        f"{item.nodeid}: Skip test on remote host "
                        f"'{host.hostname}' running in FIPS mode: {reason}"
                    )

            if mark.name == "skip_if_not_hostselinux":
                if not host.is_selinux_enabled:
                    pytest.skip(
                        f"{item.nodeid}: Skip test on remote host "
                        f"'{host.hostname}' not running in SELinux mode: "
                        f"{reason}"
                    )

            if mark.name == "skip_if_host":
                condition_cb = mark.kwargs["condition_cb"]
                if not callable(condition_cb):
                    raise TypeError("condition_cb should be callable")

                if condition_cb(host):
                    pytest.skip(
                        f"{item.nodeid}: Skip test on remote host "
                        f"'{host.hostname}': {reason}"
                    )

@pytest.fixture
def tempdir(request: FixtureRequest) -> str:
    tempdir = tempfile.mkdtemp()

    def fin() -> None:
        shutil.rmtree(tempdir)

    request.addfinalizer(fin)
    return tempdir
