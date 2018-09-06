#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from ipaplatform.paths import paths
from ipalib.basentpconf import BaseNTPClient, BaseNTPServer
from ipalib.ntpmethods import ntp_service


class ChronyClient(BaseNTPClient):
    sync_attempt_count = 3

    def __init__(self):
        super(ChronyClient, self).__init__(
            ntp_confile=paths.CHRONY_CONF,
            ntp_bin=paths.CHRONYC,
            pre_args=[paths.CHRONYC, 'waitsync',
                      str(self.sync_attempt_count), '-d'],
        )


class ChronyServer(BaseNTPServer):
    def __init__(self):
        super(ChronyServer, self).__init__(
            service_name=ntp_service['service'],
            ntp_confile=paths.CHRONY_CONF,
            ntp_bin=paths.CHRONYD,
            flag='-q',
            opts=['allow all'],
        )
