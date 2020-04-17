#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from ipaplatform.paths import paths
from ipaclient.install.clintpconf import BaseNTPClient


class ChronyClient(BaseNTPClient):
    def __init__(self):
        # chrony attempt count to sync with configured servers. Each attempt is
        # retried after $interval seconds.
        # 4 attempts with 3s interval result in a maximum delay of 9 seconds.
        sync_attempt_count = 4
        sync_attempt_interval = 3

        super(ChronyClient, self).__init__(
            ntp_confile=paths.CHRONY_CONF,
            post_args=[
                paths.CHRONYC, '-d', 'waitsync',
                # max-tries, max-correction, max-skew, interval
                str(sync_attempt_count), '0', '0', str(sync_attempt_interval)
            ]
        )


class NTPDClient(BaseNTPClient):
    def __init__(self):
        super(NTPDClient, self).__init__(
            ntp_confile=paths.NTPD_CONF,
        )


class OpenNTPDClient(BaseNTPClient):
    def __init__(self):
        super(OpenNTPDClient, self).__init__(
            ntp_confile=paths.ONTPD_CONF,
        )
