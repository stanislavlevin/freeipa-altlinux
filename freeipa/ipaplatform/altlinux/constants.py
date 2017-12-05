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
This ALT Linux base platform module exports platform related constants.
'''

# Fallback to default path definitions
from ipaplatform.base.constants import BaseConstantsNamespace


class ALTLinuxConstantsNamespace(BaseConstantsNamespace):
    HTTPD_USER = "apache2"
    HTTPD_GROUP = "apache2"
    ODS_USER = "_opendnssec"
    ODS_GROUP ="_opendnssec"
    SSSD_USER = "_sssd"

constants = ALTLinuxConstantsNamespace()
