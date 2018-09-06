#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from importlib import import_module
from ipalib.ntpmethods import TIME_SERVICE


def detect_ntp_daemon():
    ntp_libs = {
        'chrony': ['chronylib', 'Chrony'],
        'ntpd': ['ntpdlib', 'NTPD'],
        'openntpd': ['ontpdlib', 'OpenNTPD'],
    }
    sys_ntp_lib = import_module('ipalib.{}'.format(ntp_libs[TIME_SERVICE][0]))

    tsinst = getattr(sys_ntp_lib, ntp_libs[TIME_SERVICE][1] + 'Server')
    tsconf = getattr(sys_ntp_lib, ntp_libs[TIME_SERVICE][1] + 'Client')

    return tsinst, tsconf


NTPSERVER, NTPCLIENT = detect_ntp_daemon()


def sync_time_server(fstore, sstore, ntp_servers, ntp_pool):
    cl = NTPSERVER()

    cl.fstore = fstore
    cl.sstore = sstore
    cl.ntp_servers = ntp_servers
    cl.ntp_pool = ntp_pool

    try:
        cl.sync_time()
        return True
    except Exception:
        return False


def sync_time_client(fstore, statestore, cli_domain, ntp_servers, ntp_pool):
    cl = NTPCLIENT()

    cl.fstore = fstore
    cl.statestore = statestore
    cl.cli_domain = cli_domain
    cl.ntp_servers = ntp_servers
    cl.ntp_pool = ntp_pool

    return cl.sync_time()


def uninstall_server(fstore, sstore):
    cl = NTPSERVER()

    cl.sstore = sstore
    cl.fstore = fstore

    cl.uninstall()


def uninstall_client(fstore, sstore):
    cl = NTPCLIENT()

    cl.sstore = sstore
    cl.fstore = fstore

    cl.uninstall()
