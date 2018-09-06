#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

import shutil
from pkgutil import find_loader
import re

from ipaclient.install import ipadiscovery
from ipaserver.install.service import Service
from ipaplatform import services


def __service_control():
    service = Service(ntp_service['service'])
    return service


def __service_command():
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

    return timedata_srv[TIME_SERVICE]


def __detect_time_server():
    ts_modules = ['ntpdlib', 'ontpdlib', 'chronylib']
    ts = {
        'ntpdlib': 'ntpd',
        'ontpdlib': 'openntpd',
        'chronylib': 'chrony',
    }
    for srv in ts_modules:
        if find_loader('ipalib.%s' % srv):
            return ts[srv]

    return False


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

    ntp_service['api'].stop()
    ntp_service['api'].disable()

    if statestore:
        enabled = statestore.restore_state(ntp_service['service'], 'enabled')
        running = statestore.restore_state(ntp_service['service'], 'running')

        if enabled:
            ntp_service['api'].enable()

        if running:
            ntp_service['api'].start()


def check_timedate_services():
    for service in services.timedate_services:
        if service != ntp_service['service']:
            continue
        instance = services.service(service)
        if instance.is_enabled() or instance.is_running():
            raise NTPConflictingService(
                conflicting_service=instance.service_name
            )


def is_running():
    return ntp_service['api'].is_running()


def is_enabled():
    return ntp_service['api'].is_enabled()


def force_service(statestore):
    enabled = is_enabled()

    running = is_running()

    if statestore:
        statestore.backup_state(ntp_service['service'], 'enabled', enabled)
        statestore.backup_state(ntp_service['service'], 'running', running)

    if running:
        ntp_service['api'].stop()

    if enabled:
        ntp_service['api'].disable()


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
    return confile_params[TIME_SERVICE]


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
    if service_control.is_configured():
        service_control.print_msg("Unconfiguring %s"
                                  % service_control.service_name)

    restore_state(statestore, fstore, ntp_confile, logger)


class NTPConfigurationError(Exception):
    pass


class NTPConflictingService(NTPConfigurationError):
    def __init__(self, message='', conflicting_service=None):
        super(NTPConflictingService, self).__init__(self, message)
        self.conflicting_service = conflicting_service


TIME_SERVICE = __detect_time_server()
ntp_service = __service_command()
service_control = __service_control()
