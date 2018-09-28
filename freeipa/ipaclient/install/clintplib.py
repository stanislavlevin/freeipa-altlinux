#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from ipaplatform.paths import paths
from ipaclient.install.clientntpconf import BaseNTPClient


class ChronyClient(BaseNTPClient):
    sync_attempt_count = 3

    def __init__(self):
        super(ChronyClient, self).__init__(
            ntp_confile=paths.CHRONY_CONF,
            ntp_bin=paths.CHRONYC,
            pre_args=[paths.CHRONYC, 'waitsync',
                      str(self.sync_attempt_count), '-d'],
        )


class NTPDClient(BaseNTPClient):
    def __init__(self):
        super(NTPDClient, self).__init__(
            ntp_confile=paths.NTPD_CONF,
            ntp_bin=paths.NTPD,
            timeout=15,
            flag='-qgc'
        )


class OpenNTPDClient(BaseNTPClient):
    def __init__(self):
        super(OpenNTPDClient, self).__init__(
            ntp_confile=paths.ONTPD_CONF,
            ntp_bin=paths.NTPD,
            timeout=15,
            flag='-f'
        )
