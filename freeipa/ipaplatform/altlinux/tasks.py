# Authors:
#   Mikhail Efremov <sem@altlinux.org>
#
# Copyright (C) 2016  Mikhail Efremov
# see file 'COPYING' for use and warranty information
# Based on ipaplatform/redhat/tasks.py
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
This module contains default ALT Linux specific implementations of system tasks.
'''

import os

from ipapython import ipautil

from ipaplatform.redhat.tasks import RedHatTaskNamespace
from ipaplatform.paths import paths

class ALTLinuxTaskNamespace(RedHatTaskNamespace):

    # TODO: insert, reload, remove ca cert update
    def reload_systemwide_ca_store(self):
        return True

    def insert_ca_certs_into_systemwide_ca_store(self, ca_certs):
        return True

    def remove_ca_certs_from_systemwide_ca_store(self):
        return True
    # END of TODO: insert, reload, remove ca cert update

    # TODO: use Alt tool like authconfig
    def restore_pre_ipa_client_configuration(self, fstore, statestore,
                                                 was_sssd_installed,
                                                 was_sssd_configured):
        return True

    def set_nisdomain(self, nisdomain):
        return True

    def modify_nsswitch_pam_stack(self, sssd, mkhomedir, statestore):
        return True

    def modify_pam_to_use_krb5(self, statestore):
        return True

    def backup_auth_configuration(self, path):
        return True

    def restore_auth_configuration(self, path):
        return True
    # END of TODO: use Alt tool like authconfig

tasks = ALTLinuxTaskNamespace()
