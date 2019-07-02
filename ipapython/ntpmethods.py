#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

import shutil
import re
import sys

# pylint: disable=import-error,no-name-in-module,ipa-forbidden-import
from ipaclient.install import ipadiscovery
from ipalib import api
# pylint: enable=import-error,no-name-in-module,ipa-forbidden-import
from ipaplatform import services
from ipapython import ipautil


def service_command():
    timedata_srv = {
        'openntpd': {
            'api': services.knownservices.ntpd,
            'service': 'ntpd',
        },
        'ntpd': {
            'api': services.knownservices.ntpd,
            'service': 'ntpd',
        },
        'chrony': {
            'api': services.knownservices.chronyd,
            'service': 'chronyd'
        }
    }

    return timedata_srv[detect_time_server()]


def detect_time_server():
    ts_modules = ['chrony', 'ntpd', 'openntpd']

    for ts in ts_modules:
        sys_ts = ipautil.run(['rpm', '-qa', ts], capture_output=True,
                             raiseonerr=False)
        if sys_ts.output:
            return ts

    print("NTP daemon not found in your system. "
          "Please, install NTP daemon and try again.")
    sys.exit(1)


def search_ntp_servers(statestore, cli_domain):
    force_service(statestore)
    ds = ipadiscovery.IPADiscovery()
    ntp_servers = ds.ipadns_search_srv(
        cli_domain,
        '_ntp._udp',
        None, False
    )

    return ntp_servers


def backup_config(ntp_confile, fstore=None):
    if fstore:
        fstore.backup_file(ntp_confile)
    else:
        shutil.copy(ntp_confile, "%s.ipasave" % ntp_confile)


def write_config(ntp_confile, content):
    fd = open(ntp_confile, "w")
    fd.write(content)
    fd.close()


def restore_state(statestore, fstore, ntp_confile, logger):
    try:
        fstore.restore_file(ntp_confile)
    except ValueError:
        logger.debug("Configuration file %s was not restored.", ntp_confile)

    service_command()['api'].stop()
    service_command()['api'].disable()

    if statestore:
        enabled = statestore.restore_state(service_command()['service'],
                                           'enabled')
        running = statestore.restore_state(service_command()['service'],
                                           'running')

        if enabled:
            service_command()['api'].enable()

        if running:
            service_command()['api'].start()


def check_timedate_services():
    for service in services.timedate_services:
        if service != service_command()['service']:
            continue
        instance = services.service(service, api)
        if instance.is_enabled() or instance.is_running():
            raise NTPConflictingService(
                conflicting_service=instance.service_name
            )


def is_running():
    return service_command()['api'].is_running()


def is_enabled():
    return service_command()['api'].is_enabled()


def force_service(statestore):
    enabled = is_enabled()

    running = is_running()

    if statestore:
        statestore.backup_state(service_command()['service'],
                                'enabled', enabled)
        statestore.backup_state(service_command()['service'],
                                'running', running)

    if running:
        service_command()['api'].stop()

    if enabled:
        service_command()['api'].disable()


def __get_confile_list(path):
    confile_list = []

    reg = re.compile(r"^(server|servers|pool|restrict)\s.*")

    with open(path) as confile:
        for line in confile:
            search_ = re.findall(reg, line)
            if not search_:
                confile_list.append(line)

    return confile_list


def __get_confile_params():
    confile_params = {
        'ntpd': {
            'server_label': 'server',
            'pool_label': 'server',
            'option': 'iburst',
        },
        'openntpd': {
            'server_label': 'server',
            'pool_label': 'servers',
            'option': '',
        },
        'chrony': {
            'server_label': 'server',
            'pool_label': 'pool',
            'option': 'iburst',
        },
    }
    return confile_params[detect_time_server()]


def set_config(path, pool=None, servers=None, opts=None):
    confile_list = __get_confile_list(path)
    confile_params = __get_confile_params()

    confile_list.append("\n### Added by IPA Installer ###\n")

    if pool:
        confile_list.append('{pool_label} {host} {option}\n'.format(
            pool_label=confile_params['pool_label'],
            host=pool,
            option=confile_params['option'],
        ))

    if servers:
        for srv in servers:
            confile_list.append('{server_label} {host} {option}\n'.format(
                server_label=confile_params['server_label'],
                host=srv,
                option=confile_params['option'],
            ))

    if opts:
        for opt in opts:
            confile_list.append('{}\n'.format(opt))

    conf_content = ''.join(confile_list)

    return conf_content


def uninstall(statestore, fstore, ntp_confile, logger):
    if statestore:
        if statestore.has_state(service_command()['service']):
            restore_state(statestore, fstore, ntp_confile, logger)


class NTPConfigurationError(Exception):
    pass


class NTPConflictingService(NTPConfigurationError):
    def __init__(self, message='', conflicting_service=None):
        super(NTPConflictingService, self).__init__(self, message)
        self.conflicting_service = conflicting_service
