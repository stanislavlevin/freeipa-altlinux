#
# Copyright (C) 2021  FreeIPA Contributors. See COPYING for license
#

"""Define dynamically populated Host's PlatformNameSpace"""


class HostPlatformNameSpace:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        items = (f"{k}={v!r}" for k, v in self.__dict__.items())
        return "{}({})".format(type(self).__name__, ", ".join(items))


class HostPlatformPaths(HostPlatformNameSpace):
    pass


class HostPlatformOSInfo(HostPlatformNameSpace):
    pass


class HostPlatformConstants(HostPlatformNameSpace):
    pass


class HostPlatformKnownservices(HostPlatformNameSpace):
    def __getitem__(self, key):
        return self.__dict__[key]

    def get(self, key, default=None):
        try:
            return self.__dict__[key]
        except KeyError:
            return default
