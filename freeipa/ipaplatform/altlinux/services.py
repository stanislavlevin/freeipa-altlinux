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

from ipaplatform.redhat import services as redhat_services

# Mappings from service names as FreeIPA code references to these services
# to their actual systemd service names
altlinux_system_units = redhat_services.redhat_system_units.copy()

altlinux_system_units['named'] = 'bind.service'
altlinux_system_units['httpd'] = 'httpd2.service'
altlinux_system_units['rpcgssd'] = 'rpc-gssd.service'
altlinux_system_units['rpcidmapd'] = 'nfs-idmapd.service'

# Service classes that implement ALT Linux specific behaviour

class ALTLinuxService(redhat_services.RedHatService):
    system_units = altlinux_system_units

class ALTLinuxNoService(redhat_services.RedHatService):
    @staticmethod
    def start():
        return True

    @staticmethod
    def stop():
        return True

    @staticmethod
    def restart():
        return True

    @staticmethod
    def disable():
        return True

def altlinux_service_class_factory(name, api=None):
    if name in ('named', 'httpd', 'rpcgssd', 'rpcidmapd'):
        return ALTLinuxService(name, api) 
    if name in ('domainname', 'named-pkcs11', 'named-regular'):
        return ALTLinuxNoService(name, api)
    return redhat_services.redhat_service_class_factory(name, api)

# Magicdict containing ALTLinuxNoService instances.

class ALTLinuxServices(redhat_services.RedHatServices):
    def service_class_factory(self, name, api=None):
        return altlinux_service_class_factory(name, api)

# System may support more time&date services. FreeIPA supports ntpd only, other
# services will be disabled during IPA installation
timedate_services = ['ntpd', 'chronyd', 'openntpd']

httpd_modules = [
        "nss", "auth_gssapi", "rewrite", "wsgi", "proxy", "filter",
        "deflate", "headers", "authn_core", "authz_user", "expires",
        "lookup_identity", "session", "session_cookie", "proxy_ajp",
        "proxy_http"
        ]

service = altlinux_service_class_factory
knownservices = ALTLinuxServices()
