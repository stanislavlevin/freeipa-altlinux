#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

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
    NAMED_DATA_DIR = "/var/lib/bind/data/"
    NAMED_ZONE_COMMENT = "//"
    # ntpd init variable used for daemon options
    NTPD_OPTS_VAR = "NTPD_ARGS"
    # quote used for daemon options
    NTPD_OPTS_QUOTE = "\""

constants = ALTLinuxConstantsNamespace()
