#!/bin/bash -eu

function install_debuginfo() {
    apt-get update && \
    apt-get install -y \
        gdb \
        systemd-coredump \
        ${IPA_TESTS_REPO_PATH}/dist/rpms_debuginfo/*.rpm \
        389-ds-base-debuginfo \
        apache2-base-debuginfo \
        apache2-mod_auth_gssapi-debuginfo \
        apache2-mod_ssl-debuginfo \
        apache2-mod_wsgi-py3-debuginfo \
        apache2-mods-debuginfo \
        bind-debuginfo \
        bind-utils-debuginfo \
        bind-dyndb-ldap-debuginfo \
        certmonger-debuginfo \
        gssproxy-debuginfo \
        krb5-kdc-debuginfo \
        krb5-kinit-debuginfo \
        samba-dc-mitkrb5-debuginfo \
        sssd-debuginfo
}
