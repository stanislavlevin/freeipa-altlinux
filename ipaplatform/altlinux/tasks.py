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


class ALTLinuxTaskNamespace(RedHatTaskNamespace):
    def restore_pre_ipa_client_configuration(self, fstore, statestore,
                                             was_sssd_installed,
                                             was_sssd_configured):
        return True

    def set_nisdomain(self, nisdomain):
        return True

    def modify_nsswitch_pam_stack(self, sssd, mkhomedir, statestore,
                                  sudo=True):
        return True

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
