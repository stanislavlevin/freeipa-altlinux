# Authors: Karl MacMillan <kmacmillan@redhat.com>
#
# Copyright (C) 2007  Red Hat
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
#
import logging
import os
import shutil

from ipalib import api
from ipapython import ipautil
from ipaplatform.tasks import tasks
from ipaplatform import services
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

ntp_conf = """# sample ntpd configuration file, see ntpd.conf(5)

# Addresses to listen on (ntpd does not listen by default)
#listen on *
#listen on 127.0.0.1
#listen on ::1

# sync to a single server
#servers ntp.example.org

# use a random selection of 8 public stratum 2 servers
# see http://twiki.ntp.org/bin/view/Servers/NTPPoolServers
$SERVERS_BLOCK
"""

ntp_sysconfig = """# Parameters for NTP daemon.
# See ntpd(8) for more details.

# Specifies additional parameters for ntpd.
NTPD_ARGS=-s
"""
ntp_step_tickers = """# Use IPA-provided NTP server for initial time
$TICKER_SERVERS_BLOCK
"""
def __backup_config(path, fstore = None):
    if fstore:
        fstore.backup_file(path)
    else:
        shutil.copy(path, "%s.ipasave" % (path))

def __write_config(path, content):
    fd = open(path, "w")
    fd.write(content)
    fd.close()

def config_ntp(ntp_servers, fstore = None, sysstore = None):
    path_step_tickers = paths.NTP_STEP_TICKERS
    path_ntp_conf = paths.NTP_CONF
    path_ntp_sysconfig = paths.SYSCONFIG_NTPD
    sub_dict = {}
    sub_dict["SERVERS_BLOCK"] = "\n".join("servers %s" % s for s in ntp_servers)
    sub_dict["TICKER_SERVERS_BLOCK"] = "\n".join(ntp_servers)

    nc = ipautil.template_str(ntp_conf, sub_dict)
    config_step_tickers = False


    if os.path.exists(path_step_tickers):
        config_step_tickers = True
        ns = ipautil.template_str(ntp_step_tickers, sub_dict)
        __backup_config(path_step_tickers, fstore)
        __write_config(path_step_tickers, ns)
        tasks.restore_context(path_step_tickers)

    if sysstore:
        module = 'ntp'
        sysstore.backup_state(module, "enabled", services.knownservices.ntpd.is_enabled())
        if config_step_tickers:
            sysstore.backup_state(module, "step-tickers", True)

    __backup_config(path_ntp_conf, fstore)
    __write_config(path_ntp_conf, nc)
    tasks.restore_context(path_ntp_conf)

    __backup_config(path_ntp_sysconfig, fstore)
    __write_config(path_ntp_sysconfig, ntp_sysconfig)
    tasks.restore_context(path_ntp_sysconfig)

    # Set the ntpd to start on boot
    services.knownservices.ntpd.enable()

    # Restart ntpd
    services.knownservices.ntpd.restart()


def synconce_ntp(server_fqdn, debug=False):
    """
    Syncs time with specified server using ntpdate.
    Primarily designed to be used before Kerberos setup
    to get time following the KDC time

    Returns True if sync was successful
    """
    ntpdate = paths.NTPDATE
    if not os.path.exists(ntpdate):
        return False

    timeout = 15

    args = [paths.BIN_TIMEOUT, str(timeout), ntpdate, server_fqdn]
    try:
        logger.info('Attempting to sync time using ntpdate.  '
                    'Will timeout after %d seconds', timeout)
        ipautil.run(args)
        return True
    except ipautil.CalledProcessError as e:
        if e.returncode == 124:
            logger.debug('Process did not complete before timeout')
        return False


class NTPConfigurationError(Exception):
    pass

class NTPConflictingService(NTPConfigurationError):
    def __init__(self, message='', conflicting_service=None):
        super(NTPConflictingService, self).__init__(self, message)
        self.conflicting_service = conflicting_service

def check_timedate_services():
    """
    System may contain conflicting services used for time&date synchronization.
    As IPA server/client supports only ntpd, make sure that other services are
    not enabled to prevent conflicts. For example when both chronyd and ntpd
    are enabled, systemd would always start only chronyd to manage system
    time&date which would make IPA configuration of ntpd ineffective.

    Reference links:
      https://fedorahosted.org/freeipa/ticket/2974
      http://fedoraproject.org/wiki/Features/ChronyDefaultNTP
    """
    for service in services.timedate_services:
        if service == 'ntpd':
            continue
        # Make sure that the service is not enabled
        instance = services.service(service, api)
        if instance.is_enabled() or instance.is_running():
            raise NTPConflictingService(conflicting_service=instance.service_name)

def force_ntpd(statestore):
    """
    Force ntpd configuration and disable and stop any other conflicting
    time&date service
    """
    for service in services.timedate_services:
        if service == 'ntpd':
            continue
        instance = services.service(service, api)
        enabled = instance.is_enabled()
        running = instance.is_running()

        if enabled or running:
            statestore.backup_state(instance.service_name, 'enabled', enabled)
            statestore.backup_state(instance.service_name, 'running', running)

            if running:
                instance.stop()

            if enabled:
                instance.disable()

def restore_forced_ntpd(statestore):
    """
    Restore from --force-ntpd installation and enable/start service that were
    disabled/stopped during installation
    """
    for service in services.timedate_services:
        if service == 'ntpd':
            continue
        if statestore.has_state(service):
            instance = services.service(service, api)
            enabled = statestore.restore_state(instance.service_name, 'enabled')
            running = statestore.restore_state(instance.service_name, 'running')
            if enabled:
                instance.enable()
            if running:
                instance.start()
