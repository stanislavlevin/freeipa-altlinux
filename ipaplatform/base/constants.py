#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

'''
This base platform module exports platform dependant constants.
'''
import sys


class BaseConstantsNamespace(object):
    IS_64BITS = sys.maxsize > 2 ** 32
    DEFAULT_ADMIN_SHELL = '/bin/bash'
    DEFAULT_SHELL = '/bin/sh'
    DS_USER = 'dirsrv'
    DS_GROUP = 'dirsrv'
    HTTPD_USER = "apache"
    HTTPD_GROUP = "apache"
    GSSPROXY_USER = "root"
    IPA_ADTRUST_PACKAGE_NAME = "freeipa-server-trust-ad"
    IPA_DNS_PACKAGE_NAME = "freeipa-server-dns"
    KDCPROXY_USER = "kdcproxy"
    NAMED_USER = "named"
    NAMED_GROUP = "named"
    NAMED_DATA_DIR = "data/"
    NAMED_ZONE_COMMENT = ""
    PKI_USER = 'pkiuser'
    PKI_GROUP = 'pkiuser'
    # ntpd init variable used for daemon options
    NTPD_OPTS_VAR = "OPTIONS"
    # quote used for daemon options
    NTPD_OPTS_QUOTE = "\""
    ODS_USER = "ods"
    ODS_GROUP = "ods"
    # nfsd init variable used to enable kerberized NFS
    SECURE_NFS_VAR = "SECURE_NFS"
    SELINUX_BOOLEAN_ADTRUST = {
        'samba_portmapper': 'on',
    }
    SELINUX_BOOLEAN_HTTPD = {
        'httpd_can_network_connect': 'on',
        'httpd_manage_ipa': 'on',
        'httpd_run_ipa': 'on',
        'httpd_dbus_sssd': 'on',
    }
    SELINUX_MCS_MAX = 1023
    SELINUX_MCS_REGEX = r"^c(\d+)([.,-]c(\d+))*$"
    SELINUX_MLS_MAX = 15
    SELINUX_MLS_REGEX = r"^s(\d+)(-s(\d+))?$"
    SELINUX_USER_REGEX = r"^[a-zA-Z][a-zA-Z_\.]*$"
    SELINUX_USERMAP_DEFAULT = "unconfined_u:s0-s0:c0.c1023"
    SELINUX_USERMAP_ORDER = (
        "guest_u:s0"
        "$xguest_u:s0"
        "$user_u:s0"
        "$staff_u:s0-s0:c0.c1023"
        "$sysadm_u:s0-s0:c0.c1023"
        "$unconfined_u:s0-s0:c0.c1023"
    )
    SSSD_USER = "sssd"
    # WSGI module override, only used on Fedora
    MOD_WSGI_PYTHON2 = None
    MOD_WSGI_PYTHON3 = None
    # WSGIDaemonProcess process count. On 64bit platforms, each process
    # consumes about 110 MB RSS, from which are about 35 MB shared.
    WSGI_PROCESSES = 4 if IS_64BITS else 2
    # high ciphers without RC4, MD5, TripleDES, pre-shared key, secure
    # remote password, and DSA cert authentication.
    TLS_HIGH_CIPHERS = "HIGH:!aNULL:!eNULL:!MD5:!RC4:!3DES:!PSK:!SRP:!aDSS"
    HTTPD_IPA_MODULES = None
    HTTPD_IPA_CONFL_MODULES = None


constants = BaseConstantsNamespace()
