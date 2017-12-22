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
    GENERATE_RNDC_KEY = "/bin/true"
    SYSTEMCTL = "/sbin/systemctl"
    BIN_HOSTNAMECTL = "/usr/bin/hostnamectl"
    BIN_NISDOMAINNAME = "/bin/nisdomainname"
    ETC_ALTLINUX_RELEASE = "/etc/altlinux-release"
    ETC_HOSTNAME = "/etc/hostname"
    ETC_HTTPD_DIR = "/etc/httpd2"
    HTTPD_ALIAS_DIR = "/etc/httpd2/conf/nss"
    HTTPD_CONF_D_DIR = "/etc/httpd2/conf/extra-enabled"
    HTTPD_IPA_KDCPROXY_CONF_SYMLINK = "/etc/httpd2/conf/extra-enabled/ipa-kdc-proxy.conf"
    HTTPD_IPA_PKI_PROXY_CONF = "/etc/httpd2/conf/extra-enabled/ipa-pki-proxy.conf"
    HTTPD_IPA_REWRITE_CONF = "/etc/httpd2/conf/ipa-rewrite.conf"
    HTTPD_IPA_CONF = "/etc/httpd2/conf/sites-available/ipa.conf"
    HTTPD_NSS_CONF = "/etc/httpd2/conf/mods-available/nss.conf"
    HTTPD_SSL_CONF = "/etc/httpd2/conf/extra-available/ssl.conf"
    OLD_IPA_KEYTAB = "/etc/httpd2/conf/ipa.keytab"
    HTTPD_PASSWORD_CONF = "/etc/httpd2/conf/password.conf"
    SYSTEMD_SYSTEM_HTTPD_D_DIR = "/etc/systemd/system/httpd2.service.d"
    SYSTEMD_SYSTEM_HTTPD_IPA_CONF = "/etc/systemd/system/httpd2.service.d/ipa.conf"
    HTTPD = "/usr/sbin/httpd2"
    VAR_LOG_HTTPD_DIR = "/var/log/httpd2"
    VAR_LOG_HTTPD_ERROR = "/var/log/httpd2/error_log"
    SYSCONFIG_HTTPD = "/etc/sysconfig/httpd2"
    NAMED_PKCS11 = "/bin/true"
    NAMED_CONF = "/etc/bind/named.conf"
    NAMED_VAR_DIR = "/etc/bind/zone"
    NAMED_KEYTAB = "/etc/named.keytab"
    NAMED_RFC1912_ZONES = "/etc/bind/rfc1912.conf"
    NAMED_ROOT_KEY = "/etc/bind.keys"
    NAMED_BINDKEYS_FILE = "/etc/bind.keys"
    NAMED_MANAGED_KEYS_DIR = "/var/lib/bind/dynamic"
    NAMED_PID = "/var/run/named.pid"
    SYSCONFIG_NAMED = "/etc/sysconfig/bind"
    BIND_LDAP_DNS_IPA_WORKDIR = "/var/lib/bind/zone/dyndb-ldap/ipa/"
    BIND_LDAP_DNS_ZONE_WORKDIR = "/var/lib/bind/zone/dyndb-ldap/ipa/master/"
    VAR_OPENDNSSEC_DIR = "/var/lib/opendnssec"
    OPENDNSSEC_KASP_DB = "/var/lib/opendnssec/kasp.db"
    IPA_ODS_EXPORTER_CCACHE = "/var/lib/opendnssec/tmp/ipa-ods-exporter.ccache"
    DNSSEC_KEYFROMLABEL = "/usr/sbin/dnssec-keyfromlabel"
    NTP_CONF = "/etc/ntpd.conf"
    SSH_CONFIG_DIR = "/etc/openssh"
    SSH_CONFIG = "/etc/openssh/ssh_config"
    SSHD_CONFIG = "/etc/openssh/sshd_config"
    CHROMIUM_BROWSER = "/usr/bin/chromium"
    LIB_SYSTEMD_SYSTEMD_DIR = "/lib/systemd/system/"
    NTPD = "/usr/sbin/ntpd"
    NTPDATE = "/usr/sbin/ntpdate"
    IPA_CUSTODIA_SOCKET = '/run/httpd2/ipa-custodia.sock'
    OLD_KRA_AGENT_PEM = "/etc/httpd2/conf/nss/kra-agent.pem"
    RESOLVCONF_CONF = '/etc/resolvconf.conf'
    VAR_KERBEROS_KRB5KDC_DIR = "/var/lib/kerberos/krb5kdc/"
    VAR_KRB5KDC_K5_REALM = "/var/lib/kerberos/krb5kdc/.k5."
    CACERT_PEM = "/var/lib/kerberos/krb5kdc/cacert.pem"
    KRB5KDC_KADM5_ACL = "/var/lib/kerberos/krb5kdc/kadm5.acl"
    KRB5KDC_KADM5_KEYTAB = "/var/lib/kerberos/krb5kdc/kadm5.keytab"
    KRB5KDC_KDC_CONF = "/var/lib/kerberos/krb5kdc/kdc.conf"
    KDC_CERT = "/var/lib/kerberos/krb5kdc/kdc.crt"
    KDC_KEY = "/var/lib/kerberos/krb5kdc/kdc.key"
    # https://docs.python.org/2/library/platform.html#cross-platform
    if sys.maxsize > 2**32:
        LIBSOFTHSM2_SO = BasePathNamespace.LIBSOFTHSM2_SO_64
        PAM_KRB5_SO = BasePathNamespace.PAM_KRB5_SO_64
        BIND_LDAP_SO = BasePathNamespace.BIND_LDAP_SO_64

paths = ALTLinuxPathNamespace()
