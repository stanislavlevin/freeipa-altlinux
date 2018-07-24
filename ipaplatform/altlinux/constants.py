#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
This ALT Linux base platform module exports platform related constants.
"""

# Fallback to default path definitions
from ipaplatform.base.constants import BaseConstantsNamespace, User, Group

__all__ = ("constants", "User", "Group")


class ALTLinuxConstantsNamespace(BaseConstantsNamespace):
    DEFAULT_SHELL = "/bin/bash"
    HTTPD_USER = User("apache2")
    HTTPD_GROUP = Group("apache2")
    ODS_USER = User("_opendnssec")
    ODS_GROUP = Group("_opendnssec")
    SSSD_USER = User("_sssd")
    NAMED_DATA_DIR = "/var/lib/bind/data/"
    NAMED_ZONE_COMMENT = "//"
    # ntpd init variable used for daemon options
    NTPD_OPTS_VAR = "NTPD_ARGS"
    # quote used for daemon options
    NTPD_OPTS_QUOTE = '"'
    SECURE_NFS_VAR = None


constants = ALTLinuxConstantsNamespace()
