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
import stat
import socket

from ipapython.ipa_log_manager import root_logger, log_mgr
from ipapython import ipautil
import ipapython.errors

from ipaplatform.constants import constants
from ipaplatform.base.tasks import BaseTaskNamespace
from ipaplatform.paths import paths

class ALTLinuxTaskNamespace(BaseTaskNamespace):

    def backup_and_replace_hostname(self, fstore, statestore, hostname):
        """
        Don't actually replace hostname at the time, just check it.
        """
        sys_hostname = socket.gethostname()
        if sys_hostname != hostname:
            raise RuntimeError('Hostname %s don\'t match system hostname %s.' % (hostname, sys_hostname))

tasks = ALTLinuxTaskNamespace()
