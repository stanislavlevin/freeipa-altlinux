#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from ipaplatform.paths import paths
from ipalib.basentpconf import BaseNTPServer
from ipalib.ntpmethods import ntp_service


class ChronyServer(BaseNTPServer):
    def __init__(self):
        super(ChronyServer, self).__init__(
            service_name=ntp_service['service'],
            ntp_confile=paths.CHRONY_CONF,
            ntp_bin=paths.CHRONYD,
            flag='-q',
            opts=['allow all'],
        )


class NTPDServer(BaseNTPServer):
    def __init__(self):
        super(NTPDServer, self).__init__(
            service_name=ntp_service['service'],
            ntp_confile=paths.NTPD_CONF,
            ntp_bin=paths.NTPD,
            flag='-gq',
            opts=['restrict -4 default nomodify',
                  'restrict -6 default nomodify'],
        )


class OpenNTPDServer(BaseNTPServer):
    def __init__(self):
        super(OpenNTPDServer, self).__init__(
            service_name=ntp_service['service'],
            ntp_confile=paths.ONTPD_CONF,
            ntp_bin=paths.NTPD,
            flag='-s',
            opts=['listen on *'],
        )
