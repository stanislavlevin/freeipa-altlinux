# Authors:
#   Mikhail Efremov <sem@altlinux.org>
#
# Copyright (C) 2016  Mikhail Efremov
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

'''
This ALT Linux base platform module exports default filesystem paths as common
in ALT Linux systems.
'''
import sys

# Fallback to default path definitions
from ipaplatform.base.paths import BasePathNamespace

class ALTLinuxPathNamespace(BasePathNamespace):
    SH = "/bin/bash"
    BIN_HOSTNAMECTL = "/usr/bin/hostnamectl"
    CACERT_PEM = "/var/lib/kerberos/krb5kdc/cacert.pem"
    CERTMONGER_DOGTAG_SUBMIT = "/usr/lib/certmonger/dogtag-submit"
    CHROMIUM_BROWSER = "/usr/bin/chromium"
    ETC_ALTLINUX_RELEASE = "/etc/altlinux-release"
    ETC_HOSTNAME = "/etc/hostname"
    ETC_HTTPD_DIR = "/etc/httpd2"
    HTTPD = "/usr/sbin/httpd2"
    HTTPD_ALIAS_DIR = "/etc/httpd2/alias"
    HTTPD_CONF_D_DIR = "/etc/httpd2/conf/"
    HTTPD_IPA_PKI_PROXY_CONF = "/etc/httpd2/conf/ipa-pki-proxy.conf"
    HTTPD_IPA_REWRITE_CONF = "/etc/httpd2/conf/ipa-rewrite.conf"
    HTTPD_IPA_KDCPROXY_CONF_SYMLINK = "/etc/httpd2/conf/ipa-kdc-proxy.conf"
    HTTPD_IPA_CONF = "/etc/httpd2/conf/ipa.conf"
    HTTPD_NSS_CONF = "/etc/httpd2/conf/nss.conf"
    HTTPD_SSL_CONF = "/etc/httpd2/conf/ssl.conf"
    HTTPD_PASSWORD_CONF = "/etc/httpd2/conf/password.conf"
    IPA_CUSTODIA_SOCKET = '/run/httpd2/ipa-custodia.sock'
    IPA_ODS_EXPORTER_CCACHE = "/var/lib/opendnssec/tmp/ipa-ods-exporter.ccache"
    KDC_CERT = "/var/lib/kerberos/krb5kdc/kdc.crt"
    KDC_KEY = "/var/lib/kerberos/krb5kdc/kdc.key"
    KRB5KDC_KDC_CONF = "/var/lib/kerberos/krb5kdc/kdc.conf"
    KRB5KDC_KADM5_ACL = "/var/lib/kerberos/krb5kdc/kadm5.acl"
    KRB5KDC_KADM5_KEYTAB = "/var/lib/kerberos/krb5kdc/kadm5.keytab"
    LIB_SYSTEMD_SYSTEMD_DIR = "/lib/systemd/system/"
    NAMED_CONF = "/var/lib/bind/etc/named.conf"
    NAMED_VAR_DIR = "/var"
    NAMED_KEYTAB = "/etc/named.keytab"
    NAMED_PID = "/var/run/named/named.pid"
    NAMED_RFC1912_ZONES = "/etc/named.rfc1912.zones"
    NAMED_ROOT_KEY = "/etc/named.root.key"
    NAMED_BINDKEYS_FILE = "/etc/bind.keys"
    NAMED_MANAGED_KEYS_DIR = "/var/named/dynamic"
    OLD_IPA_KEYTAB = "/etc/httpd2/conf/ipa.keytab"
    OLD_KRA_AGENT_PEM = "/etc/httpd2/alias/kra-agent.pem"
    OPENDNSSEC_KASP_DB = "/var/lib/opendnssec/kasp.db"
    PAM_KRB5_SO = "/lib/security/pam_krb5.so"
    PAM_KRB5_SO_64 = "/lib64/security/pam_krb5.so"
    SSH_CONFIG_DIR = "/etc/openssh"
    SSH_CONFIG = "/etc/openssh/ssh_config"
    SSHD_CONFIG = "/etc/openssh/sshd_config"
    SYSCONFIG_HTTPD = "/etc/sysconfig/httpd2"
    SYSCONFIG_NAMED = "/etc/sysconfig/bind"
    SYSTEMCTL = "/sbin/systemctl"
    SYSTEMD_SYSTEM_HTTPD_D_DIR = "/etc/systemd/system/httpd2.service.d/"
    SYSTEMD_SYSTEM_HTTPD_IPA_CONF = "/etc/systemd/system/httpd2.service.d/ipa.conf"
    VAR_KERBEROS_KRB5KDC_DIR = "/var/lib/kerberos/krb5kdc/"
    VAR_KRB5KDC_K5_REALM = "/var/lib/kerberos/krb5kdc/.k5."
    VAR_LOG_HTTPD_DIR = "/var/log/httpd2"
    VAR_OPENDNSSEC_DIR = "/var/lib/opendnssec"
    # https://docs.python.org/2/library/platform.html#cross-platform
    if sys.maxsize > 2**32:
        LIBSOFTHSM2_SO = BasePathNamespace.LIBSOFTHSM2_SO_64

paths = ALTLinuxPathNamespace()
