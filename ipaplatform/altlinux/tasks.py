#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
This module contains default ALT Linux specific implementations of system
tasks.
"""

from ipaplatform.redhat.tasks import RedHatTaskNamespace
from ipaplatform.paths import paths
from ipapython import directivesetter
from ipapython import ipautil


class ALTLinuxTaskNamespace(RedHatTaskNamespace):
    def restore_pre_ipa_client_configuration(self, fstore, statestore,
                                             was_sssd_installed,
                                             was_sssd_configured):
        """
        Restores the pre-ipa-client configuration that was modified by the
        following platform tasks:
            modify_nsswitch_pam_stack
        """
        if statestore.has_state('control'):
            value = statestore.restore_state('control', 'system-auth')
            if value is not None:
                ipautil.run(['control', 'system-auth', value])

    def set_nisdomain(self, nisdomain):
        return True

    def modify_nsswitch_pam_stack(self, sssd, mkhomedir, fstore, statestore,
                                  sudo=True):
        """
        If sssd flag is true, configure pam and nsswitch so that SSSD is used
        for retrieving user information and authentication.

        This method provides functionality similar to the authselect tool:
        https://github.com/authselect/authselect/blob/master/profiles/sssd/nsswitch.conf:

        passwd:     sss files systemd   {exclude if "with-custom-passwd"}
        group:      sss files systemd   {exclude if "with-custom-group"}
        netgroup:   sss files           {exclude if "with-custom-netgroup"}
        automount:  sss files           {exclude if "with-custom-automount"}
        services:   sss files           {exclude if "with-custom-services"}
        sudoers:    files sss           {include if "with-sudo"}
        """
        if not sssd:
            return

        # Configure nsswitch.conf
        for database in 'passwd', 'group', 'netgroup', 'automount', 'services':
            self.configure_nsswitch_database(
                fstore, database, ['sss'],
                append=False,
                default_value=['files'])
        self.configure_nsswitch_database(
            fstore, 'shadow', ['sss'],
            append=False,
            default_value=['tcb', 'files'])

        if sudo:
            # usually no-op, since 'enable_sssd_sudo' was called earlier
            self.configure_nsswitch_database(
                fstore, 'sudoers', ['sss'], default_value=['files'])

        # Configure PAM
        res = ipautil.run(['control', 'system-auth'], capture_output=True)
        statestore.backup_state('control', 'system-auth',
                                res.output.rstrip('\n'))
        ipautil.run(['control', 'system-auth', 'sss'])

    def modify_pam_to_use_krb5(self, statestore):
        return True

    def backup_auth_configuration(self, path):
        return True

    def restore_auth_configuration(self, path):
        return True

    def migrate_auth_configuration(self, statestore):
        return True

    def configure_httpd_protocol(self):
        # don't rely on SSL_PROTOCOL_DEFAULT,
        # which is set if SSLProtocol is not defined
        directivesetter.set_directive(paths.HTTPD_SSL_CONF,
                                      'SSLProtocol',
                                      'all -SSLv3 -TLSv1 -TLSv1.1',
                                      False)


tasks = ALTLinuxTaskNamespace()
