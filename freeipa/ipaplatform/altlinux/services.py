#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
Contains ALT Linux specific service class implementations.
"""
from ipaplatform.base import services as base_services
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

class ALTLinuxNoService(base_services.PlatformService):
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

service = altlinux_service_class_factory
knownservices = ALTLinuxServices()
