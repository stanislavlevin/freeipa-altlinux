#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from ipaplatform.paths import paths
from ipalib.basentpconf import BaseNTPClient, BaseNTPServer
from ipalib.ntpmethods import ntp_service


class NTPDClient(BaseNTPClient):
    def __init__(self):
        super(NTPDClient, self).__init__(
            ntp_confile=paths.NTPD_CONF,
            ntp_bin=paths.NTPD,
            timeout=15,
            flag='-qgc'
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
