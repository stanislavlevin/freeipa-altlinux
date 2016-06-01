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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Contains ALT Linux specific service class implementations.
"""

import time

from ipaplatform.tasks import tasks
from ipaplatform.base import services as base_services
from ipaplatform.redhat import services as redhat_services
from ipapython import ipautil
from ipapython.ipa_log_manager import root_logger
from ipalib import api
from ipaplatform.paths import paths

# Mappings from service names as FreeIPA code references to these services
# to their actual systemd service names
altlinux_system_units = redhat_services.redhat_system_units

altlinux_system_units['named'] = 'bind.service'
altlinux_system_units['httpd'] = 'httpd2.service'

# Service classes that implement ALT Linux specific behaviour

class ALTLinuxService(redhat_services.RedHatService):
    system_units = altlinux_system_units

# For services which have no ALT Linux counterpart
class ALTLinuxNoService(base_services.PlatformService):
    def restart(self):
        return True

    def disable(self):
        return True

class ALTLinuxSSHService(ALTLinuxService):
    def get_config_dir(self, instance_name=""):
        return '/etc/openssh'

# Function that constructs proper ALT Linux specific server classes for services
# of specified name
wellknownservices = ['certmonger', 'dirsrv', 'httpd', 'ipa', 'krb5kdc',
		'messagebus', 'nslcd', 'nscd', 'ntpd', 'portmap',
		'rpcbind', 'kadmin', 'sshd', 'autofs', 'rpcgssd',
		'rpcidmapd', 'pki_tomcatd', 'chronyd', 'domainname',
		'named', 'ods_enforcerd', 'ods_signerd']

def altlinux_service_class_factory(name):
    if name == 'dirsrv':
        return redhat_services.RedHatDirectoryService(name)
    if name == 'ipa':
        return redhat_services.RedHatIPAService(name)
    if name == 'sshd':
        return ALTLinuxSSHService(name)
    if name in ('pki-tomcatd', 'pki_tomcatd'):
        return redhat_services.RedHatCAService(name)
    if name == 'domainname':
        return ALTLinuxNoService(name)
    if name == 'portmap':
        return ALTLinuxNoService(name)
    if name == 'rpcgssd':
        return ALTLinuxNoService(name)
    if name == 'ods_enforcerd':
        return ALTLinuxNoService(name)
    if name == 'ods_signerd':
        return ALTLinuxNoService(name)
    return ALTLinuxService(name)

# Magicdict containing ALTLinuxNoService instances.

class ALTLinuxServices(base_services.KnownServices):
    def __init__(self):
        services = dict()
        for s in base_services.wellknownservices:
            services[s] = altlinux_service_class_factory(s)
        # Call base class constructor. This will lock services to read-only
        super(ALTLinuxServices, self).__init__(services)


# Objects below are expected to be exported by platform module

from ipaplatform.base.services import timedate_services
service = altlinux_service_class_factory
knownservices = ALTLinuxServices()
