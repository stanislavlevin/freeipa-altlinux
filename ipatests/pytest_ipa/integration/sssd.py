#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#
"""SSSD tasks"""

from __future__ import annotations

from contextlib import contextmanager
import os
import re
import shutil
import time
import tempfile

from pkg_resources import parse_version
try:
    # sssd in not published on PyPI
    from SSSDConfig import NoOptionError, SSSDConfig
except ImportError:
    SSSDConfig = None


from .base_tasks import create_temp_file
from .config import Domain
from ipapython import ipautil

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Iterator, Union
    from .host import Host
    # pkg_resources manually reload bundled packages
    # pylint: disable=no-name-in-module,import-error
    from pkg_resources.extern.packaging.version import Version
    # pylint: enable=no-name-in-module,import-error


if SSSDConfig is not None:
    class SimpleSSSDConfig(SSSDConfig):
        def edit_domain(
            self,
            domain_or_name: Union[Domain, str],
            option: str,
            value: Any,  # based on schema it can be str, int, bool or list
        ) -> None:
            """Add/replace/delete option in a domain section.

            :param domain_or_name: Domain object or domain name
            :param option: option name
            :param value: value to assign to option. If None, option will be
                deleted
            """
            if isinstance(domain_or_name, Domain):
                domain_name = domain_or_name.name
            else:
                domain_name = domain_or_name
            domain = self.get_domain(domain_name)
            if value is None:
                domain.remove_option(option)
            else:
                domain.set_option(option, value)
            self.save_domain(domain)

        def edit_service(
            self,
            service_name: str,
            option: str,
            value: Any,
        ) -> None:
            """Add/replace/delete option in a service section.

            :param service_name: a string
            :param option: option name
            :param value: value to assign to option. If None, option will be
                deleted
            """
            service = self.get_service(service_name)
            if value is None:
                service.remove_option(option)
            else:
                service.set_option(option, value)
            self.save_service(service)


@contextmanager
def remote_sssd_config(host: Host) -> Iterator[SimpleSSSDConfig]:
    """Context manager for editing sssd config file on a remote host.

    It provides SimpleSSSDConfig object which is automatically serialized and
    uploaded to remote host upon exit from the context.

    If exception is raised inside the context then the ini file is NOT updated
    on remote host.

    SimpleSSSDConfig is a SSSDConfig descendant with added helper methods
    for modifying options: edit_domain and edit_service.


    Example:

        with remote_sssd_config(master) as sssd_conf:
            # use helper methods
            # add/replace option
            sssd_conf.edit_domain(master.domain, 'filter_users', 'root')
            # add/replace provider option
            sssd_conf.edit_domain(master.domain, 'sudo_provider', 'ipa')
            # delete option
            sssd_conf.edit_service('pam', 'pam_verbosity', None)

            # use original methods of SSSDConfig
            domain = sssd_conf.get_domain(master.domain.name)
            domain.set_name('example.test')
            self.save_domain(domain)
        """
    fd, temp_config_file = tempfile.mkstemp()
    os.close(fd)
    try:
        current_config = host.transport.get_file_contents(
            host.ipaplatform.paths.SSSD_CONF
        )

        with open(temp_config_file, 'wb') as f:
            f.write(current_config)

        # In order to use SSSDConfig() locally we need to import the schema
        # Create a tar file with /usr/share/sssd.api.conf and
        # /usr/share/sssd/sssd.api.d
        tmpname = create_temp_file(host)
        host.run_command(
            ['tar', 'cJvf', tmpname,
             'sssd.api.conf',
             'sssd.api.d'],
            log_stdout=False, cwd="/usr/share/sssd")
        # fetch tar file
        tar_dir = tempfile.mkdtemp()
        tarname = os.path.join(tar_dir, "sssd_schema.tar.xz")
        with open(tarname, 'wb') as f:
            f.write(host.get_file_contents(tmpname))
        # delete from remote
        host.run_command(['rm', '-f', tmpname])
        # Unpack on the local side
        ipautil.run(["tar", 'xJvf', tarname], cwd=tar_dir)
        os.unlink(tarname)

        # Use the imported schema
        sssd_config = SimpleSSSDConfig(
            schemafile=os.path.join(tar_dir, "sssd.api.conf"),
            schemaplugindir=os.path.join(tar_dir, "sssd.api.d"))
        sssd_config.import_config(temp_config_file)

        yield sssd_config

        new_config = sssd_config.dump(sssd_config.opts).encode('utf-8')
        host.transport.put_file_contents(
            host.ipaplatform.paths.SSSD_CONF, new_config
        )
    finally:
        try:
            os.remove(temp_config_file)
            shutil.rmtree(tar_dir)
        except OSError:
            pass


def setup_sssd_conf(host: Host) -> None:
    """
    Configures sssd
    """
    with remote_sssd_config(host) as sssd_config:
        # sssd 2.5.0 https://github.com/SSSD/sssd/issues/5635
        try:
            sssd_config.edit_domain(host.domain, "ldap_sudo_random_offset", 0)
        except NoOptionError:
            # sssd doesn't support ldap_sudo_random_offset
            pass

        for sssd_service_name in sssd_config.list_services():
            sssd_config.edit_service(sssd_service_name, "debug_level", 7)

        for sssd_domain_name in sssd_config.list_domains():
            sssd_config.edit_domain(sssd_domain_name, "debug_level", 7)

    # Clear the cache and restart SSSD
    clear_sssd_cache(host)


def clear_sssd_cache(host: Host) -> None:
    """
    Clears SSSD cache by removing the cache files. Restarts SSSD.
    """

    systemd_available = host.transport.file_exists(
        host.ipaplatform.paths.SYSTEMCTL
    )

    if systemd_available:
        host.systemctl.stop("sssd")
    else:
        host.run_command([host.ipaplatform.paths.SBIN_SERVICE, 'sssd', 'stop'])

    host.run_command(
        "find /var/lib/sss/db -name '*.ldb' | xargs rm -fv"
    )
    host.run_command(
        [
            "rm",
            "-fv",
            host.ipaplatform.paths.SSSD_MC_GROUP,
            host.ipaplatform.paths.SSSD_MC_PASSWD,
            host.ipaplatform.paths.SSSD_MC_INITGROUPS,
        ],
    )

    if systemd_available:
        host.systemctl.start("sssd")
    else:
        host.run_command(
            [host.ipaplatform.paths.SBIN_SERVICE, 'sssd', 'start']
        )

    # To avoid false negatives due to SSSD not responding yet
    time.sleep(10)


def check_if_sssd_is_online(host: Host) -> bool:
    """Check whether SSSD considers the IPA domain online.

    Analyse sssctl domain-status <domain>'s output to see if SSSD considers
    the IPA domain of the host online.

    Could be extended for Trust domains as well.
    """
    pattern = re.compile(r'Online status: (?P<state>.*)\n')
    result = host.run_command(
        [
            host.ipaplatform.paths.SSSCTL,
            "domain-status",
            host.domain.name,
            "-o",
        ]
    )
    match = pattern.search(result.stdout_text)
    if match is None:
        raise RuntimeError(
            "Can't understand Online status of IPA in sssctl.\n"
            f"stdout: '{result.stdout_text}'\n"
            f"stderr: '{result.stderr_text}'"
        )

    state = match.group('state')
    return state == 'Online'


def wait_for_sssd_domain_status_online(
    host: Host, timeout: int = 120
) -> None:
    """Wait up to timeout (in seconds) for sssd domain status to become Online

    The method is checking the Online Status of the domain as displayed by
    the command sssctl domain-status <domain> -o and returns successfully
    when the status is Online.
    This call is useful for instance when 389-ds has been stopped and restarted
    as SSSD may need a while before it reconnects and switches from Offline
    mode to Online.
    """
    for _i in range(0, timeout, 5):
        if check_if_sssd_is_online(host):
            break
        time.sleep(5)
    else:
        raise RuntimeError("SSSD still offline")


def get_sssd_version(host: Host) -> Version:
    """Get sssd version on remote host."""
    version = host.run_command('sssd --version').stdout_text.strip()
    return parse_version(version)
