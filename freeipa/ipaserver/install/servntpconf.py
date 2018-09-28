#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

from logging import getLogger

from ipaplatform.paths import paths
from ipapython import ipautil
from ipalib.install import sysrestore
from ipaserver.install import service
from ipapython import ntpmethods
from ipapython.ntpmethods import TIME_SERVICE

logger = getLogger(__name__)


class BaseNTPServer(service.Service):
    timeout = 15

    def __init__(self, service_name, ntp_confile=None, fstore=None,
                 ntp_bin=None, ntp_servers=None, ntp_pool=None,
                 sstore=None, flag=None, opts=None):
        super(BaseNTPServer, self).__init__(
            service_name=service_name,
            fstore=fstore,
            service_desc="NTP daemon",
            sstore=sstore,
        )

        self.ntp_confile = ntp_confile
        self.ntp_servers = ntp_servers
        self.ntp_pool = ntp_pool
        self.ntp_bin = ntp_bin
        self.flag = flag
        self.opts = opts

        self.args = [paths.BIN_TIMEOUT, str(self.timeout),
                     self.ntp_bin, self.flag]

        if not fstore:
            self.fstore = sysrestore.FileStore(paths.SYSRESTORE)

    def __configure_ntp(self):

        logger.debug("Backing up %s", self.ntp_confile)
        ntpmethods.backup_config(self.ntp_confile, self.fstore)

        logger.debug("Configuring %s", TIME_SERVICE)

        enabled = ntpmethods.ntp_service['api'].is_enabled()
        running = ntpmethods.ntp_service['api'].is_running()

        if self.sstore:
            self.sstore.backup_state(ntpmethods.ntp_service['service'],
                                     'enabled', enabled)
            self.sstore.backup_state(ntpmethods.ntp_service['service'],
                                     'running', running)

        if not self.ntp_servers and not self.ntp_pool:
            self.ntp_pool = "pool.ntp.org"

        config_content = ntpmethods.set_config(
            path=self.ntp_confile,
            pool=self.ntp_pool,
            servers=self.ntp_servers,
            opts=self.opts,
        )

        logger.debug("Writing configuration to %s", self.ntp_confile)

        ntpmethods.ntp_service['api'].stop()
        ntpmethods.write_config(self.ntp_confile, config_content)

    def __start_sync(self):
        logger.debug("Sync time with %s", TIME_SERVICE)
        ipautil.run(self.args)

    def sync_time(self):
        self.step("stopping %s" % self.service_name, self.stop)
        self.step("writing configuration", self.__configure_ntp)
        self.step("configuring %s to start on boot"
                  % self.service_name, self.enable)
        self.step("synchronization time with %s"
                  % TIME_SERVICE, self.__start_sync)
        self.step("starting %s" % self.service_name, self.start)

        self.start_creation()

    def uninstall(self):
        ntpmethods.uninstall(
            self.sstore, self.fstore, self.ntp_confile, logger
        )
