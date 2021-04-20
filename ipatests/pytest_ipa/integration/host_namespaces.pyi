#
# Copyright (C) 2021  FreeIPA Contributors. See COPYING for license
#
"""Define stubs for dynamically populated Host's PlatformNameSpaces"""

from typing import Any, List, TypedDict
from ._types import HostPlatformService


class HostPlatformNameSpace:
    def __init__(self, **kwargs: Any) -> None: ...


class HostPlatformPaths(HostPlatformNameSpace):
    BIN_CURL: str
    CA_CRT: str
    CA_CS_CFG_PATH: str
    CERTMONGER_REQUESTS_DIR: str
    CERTUTIL: str
    CHRONY_CONF: str
    CRYPTO_POLICY_OPENSSLCNF_FILE: str
    DNSSEC_TRUSTED_KEY: str
    DOGTAG_ADMIN_P12: str
    DOGTAG_IPA_CA_RENEW_AGENT_SUBMIT: str
    DSCTL: str
    ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE: str
    ETC_HOSTNAME: str
    GETENFORCE: str
    GZIP: str
    HOSTS: str
    HTTP_KEYTAB: str
    HTTPD_CERT_FILE: str
    HTTPD_IPA_CONF: str
    HTTPD_KEY_FILE: str
    HTTPD_PASSWD_FILE_FMT: str
    HTTPD_SSL_CONF: str
    IPA_CA_CRT: str
    IPA_CA_CSR: str
    IPA_CACERT_MANAGE: str
    IPA_CCACHES: str
    IPA_CERTUPDATE: str
    IPA_CLIENT_SYSRESTORE: str
    IPA_CUSTODIA_AUDIT_LOG: str
    IPA_CUSTODIA_CHECK: str
    IPA_CUSTODIA_CONF: str
    IPA_CUSTODIA_KEYS: str
    IPA_GETCERT: str
    IPA_NSSDB_PWDFILE_TXT: str
    IPA_NSSDB_DIR: str
    IPA_P11_KIT: str
    IPA_RENEWAL_LOCK: str
    IPABACKUP_LOG: str
    IPACLIENT_INSTALL_LOG: str
    IPACLIENT_UNINSTALL_LOG: str
    IPACLIENTSAMBA_INSTALL_LOG: str
    IPACLIENTSAMBA_UNINSTALL_LOG: str
    IPACTL: str
    IPAEPN_LOG: str
    IPAREPLICA_INSTALL_LOG: str
    IPAREPLICA_CONNCHECK_LOG: str
    IPASERVER_ADTRUST_INSTALL_LOG: str
    IPASERVER_DNS_INSTALL_LOG: str
    IPASERVER_INSTALL_LOG: str
    IPASERVER_KRA_INSTALL_LOG: str
    IPASERVER_UNINSTALL_LOG: str
    IPAREPLICA_CA_INSTALL_LOG: str
    IPARESTORE_LOG: str
    IPATRUSTENABLEAGENT_LOG: str
    IPAUPGRADE_LOG: str
    KADMIND_LOG: str
    KDC_CERT: str
    KDCPROXY_CONFIG: str
    KLIST: str
    KRB5_CONF: str
    KRB5_KEYTAB: str
    KRB5KDC_LOG: str
    KTUTIL: str
    LDAPPASSWD: str
    LETS_ENCRYPT_LOG: str
    LIBEXEC_IPA_DIR: str
    NAMED_CONF: str
    NAMED_CUSTOM_CONF: str
    NAMED_CUSTOM_OPTIONS_CONF: str
    NAMED_CRYPTO_POLICY_FILE: str
    NAMED_LOGGING_OPTIONS_CONF: str
    NAMED_VAR_DIR: str
    NETWORK_MANAGER_CONFIG: str
    NETWORK_MANAGER_CONFIG_DIR: str
    NSS_DB_DIR: str
    OPENLDAP_LDAP_CONF: str
    OPENSSL: str
    OPENSSL_CERTS_DIR: str
    OPENSSL_DIR: str
    OPENSSL_PRIVATE_DIR: str
    PKI_CA_PUBLISH_DIR: str
    PKI_TOMCAT: str
    PKI_TOMCAT_ALIAS_DIR: str
    PKI_TOMCAT_ALIAS_PWDFILE_TXT: str
    PKI_TOMCAT_SERVER_XML: str
    PROC_FIPS_ENABLED: str
    RA_AGENT_PEM: str
    REPLICA_INFO_GPG_TEMPLATE: str
    RESOLV_CONF: str
    ROOT_IPA_CSR: str
    SAMBA_KEYTAB: str
    SBIN_SERVICE: str
    SELINUXENABLED: str
    SEMODULE: str
    SMB_CONF: str
    SSS_SSH_AUTHORIZEDKEYS: str
    SSSCTL: str
    SSSD_CONF: str
    SSSD_KEYTABS_DIR: str
    SSSD_MC_INITGROUPS: str
    SSSD_MC_GROUP: str
    SSSD_MC_PASSWD: str
    SYSCONFIG_PKI_TOMCAT: str
    SYSCONFIG_PKI_TOMCAT_PKI_TOMCAT_DIR: str
    SYSRESTORE: str
    SYSTEMCTL: str
    SYSTEMD_RESOLVED_CONF: str
    SYSTEMD_RESOLVED_CONF_DIR: str
    SYSUPGRADE_STATEFILE_DIR: str
    SYSUPGRADE_STATEFILE_FILE: str
    TMP: str
    TOMCAT_TOPLEVEL_DIR: str
    VAR_LOG_AUDIT: str
    VAR_LOG_DIRSRV: str
    VAR_LOG_PKI_DIR: str
    VAR_LIB_PKI_TOMCAT_DIR: str
    VAR_LIB_SLAPD_INSTANCE_DIR_TEMPLATE: str
    VAR_LOG_HTTPD_DIR: str
    VAR_LOG_HTTPD_ERROR: str
    VAR_LOG_DIRSRV_INSTANCE_TEMPLATE: str
    VAR_LOG_SSSD_DIR: str


class HostPlatformOSInfo(HostPlatformNameSpace):
    name: str
    platform: str
    id: str
    id_like: List[str]
    version: str
    version_number: List[int]
    platform_ids: List[int]
    container: str


class HostPlatformConstants(HostPlatformNameSpace):
    DEFAULT_ADMIN_SHELL: str
    DEFAULT_SHELL: str
    DS_GROUP: str
    DS_USER: str
    HTTPD_USER: str
    IPAAPI_USER: str
    NAMED_DATA_DIR: str
    SELINUX_USERMAP_ORDER: str
    WSGI_PROCESSES: int


HostPlatformKnownservices = TypedDict(
    "HostPlatformKnownservices",
    {
        "chronyd": HostPlatformService,
        "ipa": HostPlatformService,
        "systemd-resolved": HostPlatformService,
        "NetworkManager": HostPlatformService,
    }
)
