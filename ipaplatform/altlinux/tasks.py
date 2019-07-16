#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
This module contains ALT Linux specific implementations of system tasks.
"""

from ipaplatform.redhat.tasks import RedHatTaskNamespace


class ALTLinuxTaskNamespace(RedHatTaskNamespace):

    # TODO: use Alt tool like authconfig
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

    # END of TODO: use Alt tool like authconfig


tasks = ALTLinuxTaskNamespace()
