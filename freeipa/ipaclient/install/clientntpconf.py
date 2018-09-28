import os
from logging import getLogger

from ipaplatform.tasks import tasks
from ipaplatform.paths import paths
from ipapython import ipautil
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
