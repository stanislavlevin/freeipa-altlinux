# Authors:
#   Alexander Bokovoy <abokovoy@redhat.com>
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2011-2014  Red Hat
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
This module contains default platform-specific implementations of system tasks.
'''

from __future__ import absolute_import

import logging

from pkg_resources import parse_version

from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.ipachangeconf import IPAChangeConf

logger = logging.getLogger(__name__)


class BaseTaskNamespace:

    def restore_context(self, filepath, force=False):
        """Restore SELinux security context on the given filepath.

        No return value expected.
        """
        raise NotImplementedError()

    def backup_hostname(self, fstore, statestore):
        """
        Backs up the current hostname in the statestore (so that it can be
        restored by the restore_hostname platform task).

        No return value expected.
        """

        raise NotImplementedError()

    def reload_systemwide_ca_store(self):
        """
        Reloads the systemwide CA store.

        Returns True if the operation succeeded, False otherwise.
        """

        raise NotImplementedError()

    def insert_ca_certs_into_systemwide_ca_store(self, ca_certs):
        """
        Adds CA certificates from 'ca_certs' to the systemwide CA store
        (if available on the platform).

        Returns True if the operation succeeded, False otherwise.
        """

        try:
            if self.platform_insert_ca_certs(ca_certs):
                return self.reload_systemwide_ca_store()
        except Exception:
            logger.exception('Could not populate systemwide CA store')

        return False

    def platform_insert_ca_certs(self, ca_certs):
        """
        Platform implementations override this method to implement
        population of the systemwide CA store.

        Returns True if changes were made to the CA store, False otherwise.

        Raises Exception if something went wrong.
        """
        raise NotImplementedError()

    def remove_ca_certs_from_systemwide_ca_store(self):
        """
        Removes IPA CA certificates from the systemwide CA store
        (if available on the platform).

        Returns True if the operation succeeded, False otherwise.
        """

        try:
            if self.platform_remove_ca_certs():
                return self.reload_systemwide_ca_store()
        except Exception:
            logger.exception(
                'Could not remove certificates from systemwide CA store'
            )

        return False

    def platform_remove_ca_certs(self):
        """
        Platform implementations override this method to implement
        removal of certificates from the systemwide CA store.

        Returns True if changes were made to the CA store, False otherwise.

        Raises Exception if something went wrong.
        """
        raise NotImplementedError()

    def get_svc_list_file(self):
        """
        Returns the path to the IPA service list file.
        """

        return paths.SVC_LIST_FILE

    def is_selinux_enabled(self):
        """Check if SELinux is available and enabled

        :return: True if SELinux is available and enabled
        """
        return False

    def check_selinux_status(self):
        """Checks if SELinux is available on the platform.

        If it is, this task also makes sure that restorecon tool is available.

        If SELinux is available, but restorcon tool is not installed, raises
        an RuntimeError, which suggest installing the package containing
        restorecon and rerunning the installation.

        :return: True if SELinux is available and enabled
        """
        raise NotImplementedError()

    def check_ipv6_stack_enabled(self):
        """Check whether IPv6 kernel module is loaded"""

        raise NotImplementedError()

    def detect_container(self):
        """Check if running inside a container

        :returns: container runtime or None
        :rtype: str, None
        """
        raise NotImplementedError

    def restore_hostname(self, fstore, statestore):
        """
        Restores the original hostname as backed up in the
        backup_hostname platform task.
        """

        raise NotImplementedError()

    def restore_pre_ipa_client_configuration(self, fstore, statestore,
                                             was_sssd_installed,
                                             was_sssd_configured):
        """
        Restores the pre-ipa-client configuration that was modified by the
        following platform tasks:
            modify_nsswitch_pam_stack
            modify_pam_to_use_krb5
        """

        raise NotImplementedError()

    def set_nisdomain(self, nisdomain):
        """
        Sets the NIS domain name to 'nisdomain'.
        """

        raise NotImplementedError()

    def modify_nsswitch_pam_stack(self, sssd, mkhomedir, fstore, statestore,
                                  sudo=True):
        """
        If sssd flag is true, configure pam and nsswitch so that SSSD is used
        for retrieving user information and authentication.

        Otherwise, configure pam and nsswitch to leverage pure LDAP.
        """

        raise NotImplementedError()

    def modify_pam_to_use_krb5(self, statestore):
        """
        Configure pam stack to allow kerberos authentication.
        """

        raise NotImplementedError()

    def is_nosssd_supported(self):
        """
        Check if the flag --no-sssd is supported for client install.
        """

        return True

    def backup_auth_configuration(self, path):
        """
        Create backup of access control configuration.
        :param path: store the backup here. This will be passed to
        restore_auth_configuration as well.
        """
        raise NotImplementedError()

    def restore_auth_configuration(self, path):
        """
        Restore backup of access control configuration.
        :param path: restore the backup from here.
        """
        raise NotImplementedError()

    def migrate_auth_configuration(self, statestore):
        """
        Migrate pam stack configuration to authselect.
        """

    def set_selinux_booleans(self, required_settings, backup_func=None):
        """Set the specified SELinux booleans

        :param required_settings: A dictionary mapping the boolean names
                                  to desired_values.
                                  The desired value can be 'on' or 'off',
                                  or None to leave the setting unchanged.

        :param backup_func: A function called for each boolean with two
                            arguments: the name and the previous value

        If SELinux is disabled, return False; on success returns True.

        If setting the booleans fails,
        an ipapython.errors.SetseboolError is raised.
        """

        raise NotImplementedError()

    @staticmethod
    def parse_ipa_version(version):
        """
        :param version: textual version
        :return: object implementing proper __cmp__ method for version compare
        """
        return parse_version(version)

    def set_hostname(self, hostname):
        """
        Set hostname for the system

        No return value expected, raise CalledProcessError when error occurred
        """
        raise NotImplementedError()

    def configure_httpd_service_ipa_conf(self):
        """Configure httpd service to work with IPA"""
        raise NotImplementedError()

    def configure_http_gssproxy_conf(self, ipauser):
        raise NotImplementedError()

    def configure_ipa_gssproxy_dir(self):
        raise NotImplementedError()

    def remove_httpd_service_ipa_conf(self):
        """Remove configuration of httpd service of IPA"""
        raise NotImplementedError()

    def configure_httpd_wsgi_conf(self):
        """Configure WSGI for correct Python version"""
        raise NotImplementedError()

    def configure_httpd_protocol(self):
        """Configure TLS protocols in Apache"""
        raise NotImplementedError()

    def is_fips_enabled(self):
        return False

    def add_user_to_group(self, user, group):
        logger.debug('Adding user %s to group %s', user, group)
        args = [paths.USERMOD, '-a', '-G', group, user]
        try:
            ipautil.run(args)
            logger.debug('Done adding user to group')
        except ipautil.CalledProcessError as e:
            logger.debug('Failed to add user to group: %s', e)

    def setup_httpd_logging(self):
        raise NotImplementedError()

    def systemd_daemon_reload(self):
        """Tell systemd to reload config files"""
        raise NotImplementedError

    def configure_dns_resolver(self, nameservers, searchdomains, fstore=None):
        """Configure global DNS resolver (e.g. /etc/resolv.conf)

        :param nameservers: list of IP addresses
        :param searchdomains: list of search domaons
        :param fstore: optional file store for backup
        """
        raise NotImplementedError

    def unconfigure_dns_resolver(self, fstore=None):
        """Unconfigure global DNS resolver (e.g. /etc/resolv.conf)

        :param fstore: optional file store for restore
        """
        if fstore is not None and fstore.has_file(paths.RESOLV_CONF):
            fstore.restore_file(paths.RESOLV_CONF)


    def configure_pkcs11_modules(self, fstore):
        """Disable p11-kit modules

        The p11-kit configuration injects p11-kit-proxy into all NSS
        databases. Amongst other p11-kit loads SoftHSM2 PKCS#11 provider.
        This interferes with 389-DS, certmonger, Dogtag and other services.
        For example certmonger tries to open OpenDNSSEC's SoftHSM2 token,
        although it doesn't use it at all. It also breaks Dogtag HSM support
        testing with SoftHSM2.

        IPA server does neither need nor use SoftHSM2 proxied by p11-kit.
        """
        raise NotImplementedError

    def restore_pkcs11_modules(self, fstore):
        """Restore global p11-kit modules for NSS
        """
        raise NotImplementedError

    def get_pkcs11_modules(self):
        """Return the list of module config files setup by IPA.
        """
        return ()

    def configure_nsswitch_database(self, fstore, database, services,
                                    preserve=True, append=True,
                                    default_value=()):
        """
        Edits the specified nsswitch.conf database (e.g. passwd, group,
        sudoers) to use the specified service(s).

        Arguments:
            fstore - FileStore to backup the nsswitch.conf
            database - database configuration that should be ammended,
                       e.g. 'sudoers'
            service - list of services that should be added, e.g. ['sss']
            preserve - if True, the already configured services will be
                       preserved

        The next arguments modify the behaviour if preserve=True:
            append - if True, the services will be appended, if False,
                     prepended
            default_value - list of services that are considered as default (if
                            the database is not mentioned in nsswitch.conf),
                            e.g. ['files']
        """

        # Backup the original version of nsswitch.conf, we're going to edit it
        # now
        if not fstore.has_file(paths.NSSWITCH_CONF):
            fstore.backup_file(paths.NSSWITCH_CONF)

        conf = IPAChangeConf("IPA Installer")
        conf.setOptionAssignment(':')

        if preserve:
            # Read the existing configuration
            with open(paths.NSSWITCH_CONF, 'r') as f:
                opts = conf.parse(f)
                raw_database_entry = conf.findOpts(opts, 'option', database)[1]

            # Detect the list of already configured services
            if not raw_database_entry:
                # If there is no database entry, database is not present in
                # the nsswitch.conf. Set the list of services to the
                # default list, if passed.
                configured_services = list(default_value)
            else:
                configured_services = raw_database_entry[
                    'value'].strip().split()

            # Make sure no service is added if already mentioned in the list
            added_services = [s for s in services
                              if s not in configured_services]

            # Prepend / append the list of new services
            if append:
                new_value = ' ' + ' '.join(configured_services +
                                           added_services)
            else:
                new_value = ' ' + ' '.join(added_services +
                                           configured_services)

        else:
            # Preserve not set, let's rewrite existing configuration
            new_value = ' ' + ' '.join(services)

        # Set new services as sources for database
        opts = [
            conf.setOption(database, new_value),
            conf.emptyLine(),
        ]

        conf.changeConf(paths.NSSWITCH_CONF, opts)
        logger.info("Configured %s in %s", database, paths.NSSWITCH_CONF)

    def enable_sssd_sudo(self, fstore):
        """Configure nsswitch.conf to use sssd for sudo"""
        self.configure_nsswitch_database(
            fstore, 'sudoers', ['sss'],
            default_value=['files'])

    def enable_ldap_automount(self, statestore):
        """
        Point automount to ldap in nsswitch.conf.
        This function is for non-SSSD setups only.
        """
        conf = IPAChangeConf("IPA Installer")
        conf.setOptionAssignment(':')

        with open(paths.NSSWITCH_CONF, 'r') as f:
            current_opts = conf.parse(f)
            current_nss_value = conf.findOpts(
                current_opts, name='automount', type='option'
            )[1]
            if current_nss_value is None:
                # no automount database present
                current_nss_value = False  # None cannot be backed up
            else:
                current_nss_value = current_nss_value['value']
            statestore.backup_state(
                'ipa-client-automount-nsswitch', 'previous-automount',
                current_nss_value
            )

        nss_value = ' files ldap'
        opts = [
            {
                'name': 'automount',
                'type': 'option',
                'action': 'set',
                'value': nss_value,
            },
            {'name': 'empty', 'type': 'empty'},
        ]
        conf.changeConf(paths.NSSWITCH_CONF, opts)

        logger.info("Configured %s", paths.NSSWITCH_CONF)

    def disable_ldap_automount(self, statestore):
        """Disable automount using LDAP"""
        if statestore.get_state(
            'ipa-client-automount-nsswitch', 'previous-automount'
        ) is False:
            # Previous nsswitch.conf had no automount database configured
            # so remove it.
            conf = IPAChangeConf("IPA automount installer")
            conf.setOptionAssignment(':')
            changes = [conf.rmOption('automount')]
            conf.changeConf(paths.NSSWITCH_CONF, changes)
            self.restore_context(paths.NSSWITCH_CONF)
            statestore.delete_state(
                'ipa-client-automount-nsswitch', 'previous-automount'
            )
        elif statestore.get_state(
            'ipa-client-automount-nsswitch', 'previous-automount'
        ) is not None:
            nss_value = statestore.get_state(
                'ipa-client-automount-nsswitch', 'previous-automount'
            )
            opts = [
                {
                    'name': 'automount',
                    'type': 'option',
                    'action': 'set',
                    'value': nss_value,
                },
                {'name': 'empty', 'type': 'empty'},
            ]
            conf = IPAChangeConf("IPA automount installer")
            conf.setOptionAssignment(':')
            conf.changeConf(paths.NSSWITCH_CONF, opts)
            self.restore_context(paths.NSSWITCH_CONF)
            statestore.delete_state(
                'ipa-client-automount-nsswitch', 'previous-automount'
            )

tasks = BaseTaskNamespace()
