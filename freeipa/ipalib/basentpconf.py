#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

import os
from logging import getLogger

from ipaplatform.tasks import tasks
from ipaplatform.paths import paths
from ipapython import ipautil

from ipalib.install import sysrestore
from ipaserver.install import service
from ipalib import ntpmethods
from ipalib.ntpmethods import TIME_SERVICE

logger = getLogger(__name__)


class BaseNTPClient(object):
    def __init__(self, fstore=None, ntp_confile=None, ntp_bin=None,
                 statestore=None, cli_domain=None, timeout=None,
                 flag=None, ntp_servers=None, ntp_pool=None,
                 pre_args=None, post_args=None):

        self.fstore = fstore
        self.ntp_confile = ntp_confile
        self.ntp_bin = ntp_bin
        self.statestore = statestore
        self.cli_domain = cli_domain
        self.ntp_pool = ntp_pool
        self.ntp_servers = ntp_servers
        self.timeout = str(timeout)
        self.flag = flag
        self.pre_args = pre_args
        self.post_args = post_args

        if not pre_args and not post_args:
            self.args = [paths.BIN_TIMEOUT, self.timeout,
                         self.ntp_bin, self.flag, self.ntp_confile]

    def __configure_ntp(self):

        logger.debug("Backing up %s", self.ntp_confile)
        ntpmethods.backup_config(self.ntp_confile, self.fstore)

        logger.debug("Backing up state %s", TIME_SERVICE)

        enabled = ntpmethods.ntp_service['api'].is_enabled()
        running = ntpmethods.ntp_service['api'].is_running()

        if self.statestore:
            self.statestore.backup_state(ntpmethods.ntp_service['service'],
                                         'enabled', enabled)
            self.statestore.backup_state(ntpmethods.ntp_service['service'],
                                         'running', running)

        logger.debug("Configuring %s", TIME_SERVICE)

        ntpmethods.ntp_service['api'].stop()

        ntp_servers = self.ntp_servers

        if not ntp_servers:
            ntp_servers = ntpmethods.search_ntp_servers(self.statestore,
                                                        self.cli_domain)
            if not ntp_servers:
                logger.warning("No SRV records of NTP servers found and "
                               "no NTP server or pool address was provided.")

                return False

        config_content = ntpmethods.set_config(self.ntp_confile,
                                               servers=self.ntp_servers,
                                               pool=self.ntp_pool)

        logger.debug("Writing configuration to %s", self.ntp_confile)
        ntpmethods.write_config(self.ntp_confile, config_content)

        tasks.restore_context(self.ntp_confile)

        return True

    def sync_time(self):
        configured = self.__configure_ntp()

        try:
            self.__configure_ntp()
            configured = True
        except Exception:
            pass

        if not configured:
            logger.info("%s service not configured and "
                        "IPA will be not synchronized", TIME_SERVICE)
            return False

        if not os.path.exists(self.ntp_bin):
            return False

        try:
            logger.info("Attempting to sync time with %s", TIME_SERVICE)
            logger.info("Will timeout after %s seconds", self.timeout)

            if self.pre_args:
                ipautil.run(self.pre_args)

            ntpmethods.ntp_service['api'].enable()
            ntpmethods.ntp_service['api'].start()

            if self.post_args:
                ipautil.run(self.post_args)

            return True

        except ipautil.CalledProcessError as e:
            if e.returncode == 124:
                logger.debug("Process did not complete before timeout")

            return False

    def uninstall(self):
        ntpmethods.uninstall(self.statestore, self.fstore,
                             self.ntp_confile, logger)


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
        self.fstore.backup_file(self.ntp_confile)

        logger.debug("Configuring %s", TIME_SERVICE)

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
