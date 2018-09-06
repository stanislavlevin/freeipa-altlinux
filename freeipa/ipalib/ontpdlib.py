#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from ipaplatform.paths import paths
from ipalib.basentpconf import BaseNTPClient, BaseNTPServer
from ipalib.ntpmethods import ntp_service


class OpenNTPDClient(BaseNTPClient):
    def __init__(self):
        super(OpenNTPDClient, self).__init__(
            ntp_confile=paths.ONTPD_CONF,
            ntp_bin=paths.NTPD,
            timeout=15,
            flag='-f'
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
