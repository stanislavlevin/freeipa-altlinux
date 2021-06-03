import os
import abc
import logging
import re
import textwrap
import time

from . import tasks


logger = logging.getLogger(__name__)


class Resolver(abc.ABC):
    def __init__(self, host):
        self.host = host
        self.backups = []
        self.current_state = self._get_state()
        logger.info('Obtained initial resolver state for host %s: %s',
                    self.host, self.current_state)

    def setup_resolver(self, nameservers, searchdomains=None):
        """Configure DNS resolver

        :param nameservers: IP address of nameserver or a list of addresses
        :param searchdomains: searchdomain or list of searchdomains.
               None - do not configure

        Resolver.backup() must be called prior to using this method.

        Raises exception if configuration was changed externally since last call
        to any method of Resolver class.
        """
        if len(self.backups) == 0:
            raise Exception(
                'Changing resolver state without backup is forbidden')
        self.check_state_expected()
        if isinstance(nameservers, str):
            nameservers = [nameservers]
        if isinstance(searchdomains, str):
            searchdomains = [searchdomains]
        if searchdomains is None:
            searchdomains = []
        logger.info(
            'Setting up resolver for host %s: nameservers=%s, searchdomains=%s',
            self.host, nameservers, searchdomains
        )
        state = self._make_state_from_args(nameservers, searchdomains)
        self._set_state(state)

    def backup(self):
        """Saves current configuration to stack

        Raises exception if configuration was changed externally since last call
        to any method of Resolver class.
        """
        self.check_state_expected()
        self.backups.append(self._get_state())
        logger.info(
            'Saved resolver state for host %s, number of saved states: %s',
            self.host, len(self.backups)
        )

    def restore(self):
        """Restore configuration from stack of backups.

        Raises exception if configuration was changed externally since last call
        to any method of Resolver class.
        """

        if len(self.backups) == 0:
            raise Exception('No resolver backups found for host {}'.format(
                self.host))
        self.check_state_expected()
        self._set_state(self.backups.pop())
        logger.info(
            'Restored resolver state for host %s, number of saved states: %s',
            self.host, len(self.backups)
        )

    def has_backups(self):
        """Checks if stack of backups is not empty"""
        return bool(self.backups)

    def check_state_expected(self):
        """Checks if resolver configuration has not changed.

        Raises AssertionError if actual configuration has changed since last
        call to any method of Resolver
        """
        assert self._get_state() == self.current_state, (
            'Resolver state changed unexpectedly at host {}'.format(self.host))

    def __enter__(self):
        self.backup()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.restore()

    def _set_state(self, state):
        self._apply_state(state)
        logger.info('Applying resolver state for host %s: %s', self.host, state)
        self.current_state = state

    @abc.abstractclassmethod
    def is_our_resolver(cls, host):
        """Checks if the class is appropriate for managing resolver on the host.
        """

    @abc.abstractmethod
    def _make_state_from_args(self, nameservers, searchdomains):
        """

        :param nameservers: list of ip addresses of nameservers
        :param searchdomains: list of searchdomain, can be an empty list
        :return: internal state object specific to subclass implementaion
        """

    @abc.abstractmethod
    def _get_state(self):
        """Acquire actual host configuration.

        :return: internal state object  specific to subclass implementaion
        """

    @abc.abstractmethod
    def _apply_state(self, state):
        """Apply configuration to host.

        :param state: internal state object  specific to subclass implementaion
        """

    def uses_localhost_as_dns(self):
        """Return true if the localhost is set as DNS server.

        Default implementation checks the content of /etc/resolv.conf
        """
        resolvconf = self.host.get_file_contents(
            self.host.ipaplatform.paths.RESOLV_CONF, "utf-8"
        )
        patterns = [r"^\s*nameserver\s+127\.0\.0\.1\s*$",
                    r"^\s*nameserver\s+::1\s*$"]
        return any(re.search(p, resolvconf, re.MULTILINE) for p in patterns)


class ResolvedResolver(Resolver):
    RESOLVED_RESOLV_CONF = {
        "/run/systemd/resolve/stub-resolv.conf",
        "/run/systemd/resolve/resolv.conf",
        "/lib/systemd/resolv.conf",
        "/usr/lib/systemd/resolv.conf",
    }
    RESOLVED_CONF_FILE = (
        '/etc/systemd/resolved.conf.d/zzzz-ipatests-nameservers.conf')
    RESOLVED_CONF = textwrap.dedent('''
        # generated by IPA tests
        [Resolve]
        DNS={nameservers}
        Domains=~. {searchdomains}
    ''')

    @classmethod
    def is_our_resolver(cls, host):
        res = host.run_command(
            ['stat', '--format', '%F', host.ipaplatform.paths.RESOLV_CONF])
        filetype = res.stdout_text.strip()
        if filetype == 'symbolic link':
            res = host.run_command(
                ["realpath", host.ipaplatform.paths.RESOLV_CONF]
            )
            return (res.stdout_text.strip() in cls.RESOLVED_RESOLV_CONF)
        return False

    def _restart_resolved(self):
        # Restarting service at rapid pace (which is what happens in some test
        # scenarios) can exceed the threshold configured in systemd option
        # StartLimitIntervalSec. In that case restart fails, but we can simply
        # continue trying until it succeeds
        tasks.run_repeatedly(
            self.host,
            [
                self.host.ipaplatform.paths.SYSTEMCTL,
                "restart",
                self.host.ipaplatform.knownservices[
                    "systemd-resolved"
                ].systemd_name,
            ],
            timeout=15,
        )

    def _make_state_from_args(self, nameservers, searchdomains):
        return {
            'resolved_config': self.RESOLVED_CONF.format(
                nameservers=' '.join(nameservers),
                searchdomains=' '.join(searchdomains))
        }

    def _get_state(self):
        exists = self.host.transport.file_exists(self.RESOLVED_CONF_FILE)
        return {
            'resolved_config':
                self.host.get_file_contents(self.RESOLVED_CONF_FILE, 'utf-8')
                if exists else None
        }

    def _apply_state(self, state):
        if state['resolved_config'] is None:
            self.host.run_command(['rm', '-f', self.RESOLVED_CONF_FILE])
        else:
            self.host.run_command(
                ['mkdir', '-p', os.path.dirname(self.RESOLVED_CONF_FILE)])
            self.host.put_file_contents(
                self.RESOLVED_CONF_FILE, state['resolved_config'])
        self._restart_resolved()

    def uses_localhost_as_dns(self):
        """Return true if the localhost is set as DNS server.

        When systemd-resolved is in use, the DNS can be found using
        the command resolvectldns.
        """
        dnsconf = self.host.run_command(['resolvectl', 'dns']).stdout_text
        patterns = [r"^Global:.*\s+127.0.0.1\s+.*$",
                    r"^Global:.*\s+::1\s+.*$"]
        return any(re.search(p, dnsconf, re.MULTILINE) for p in patterns)


class PlainFileResolver(Resolver):
    IPATESTS_RESOLVER_COMMENT = '# created by ipatests'

    @classmethod
    def is_our_resolver(cls, host):
        res = host.run_command(
            ['stat', '--format', '%F', host.ipaplatform.paths.RESOLV_CONF])
        filetype = res.stdout_text.strip()
        if filetype == 'regular file':
            # We want to be sure that /etc/resolv.conf is not generated
            # by NetworkManager or systemd-resolved. When it is then
            # the first line of the file is a comment of the form:
            #
            # Generated by NetworkManager
            #
            # or
            #
            # This file is managed by man:systemd-resolved(8). Do not edit.
            #
            # So we check that either first line of resolv.conf
            # is not a comment or the comment does not mention NM or
            # systemd-resolved
            resolv_conf = host.get_file_contents(
                host.ipaplatform.paths.RESOLV_CONF, "utf-8"
            )
            line = resolv_conf.splitlines()[0].strip()
            return not line.startswith('#') or all([
                'resolved' not in line,
                'NetworkManager' not in line
            ])
        return False

    def _make_state_from_args(self, nameservers, searchdomains):
        contents_lines = [self.IPATESTS_RESOLVER_COMMENT]
        contents_lines.extend('nameserver {}'.format(r) for r in nameservers)
        if searchdomains:
            contents_lines.append('search {}'.format(' '.join(searchdomains)))
        contents = '\n'.join(contents_lines)
        return {'resolv_conf': contents}

    def _get_state(self):
        return {
            'resolv_conf': self.host.get_file_contents(
                self.host.ipaplatform.paths.RESOLV_CONF, "utf-8"
            )
        }

    def _apply_state(self, state):
        self.host.put_file_contents(
            self.host.ipaplatform.paths.RESOLV_CONF, state["resolv_conf"]
        )


class NetworkManagerResolver(Resolver):
    NM_CONF_FILE = '/etc/NetworkManager/conf.d/zzzz-ipatests.conf'
    NM_CONF = textwrap.dedent('''
        # generated by IPA tests
        [main]
        dns=default

        [global-dns]
        searches={searchdomains}

        [global-dns-domain-*]
        servers={nameservers}
    ''')

    @classmethod
    def is_our_resolver(cls, host):
        res = host.run_command(
            ['stat', '--format', '%F', host.ipaplatform.paths.RESOLV_CONF])
        filetype = res.stdout_text.strip()
        if filetype == 'regular file':
            resolv_conf = host.get_file_contents(
                host.ipaplatform.paths.RESOLV_CONF, "utf-8"
            )
            return resolv_conf.startswith('# Generated by NetworkManager')
        return False

    def _restart_network_manager(self):
        # Restarting service at rapid pace (which is what happens in some test
        # scenarios) can exceed the threshold configured in systemd option
        # StartLimitIntervalSec. In that case restart fails, but we can simply
        # continue trying until it succeeds
        tasks.run_repeatedly(
            self.host,
            [
                self.host.ipaplatform.paths.SYSTEMCTL,
                "restart",
                self.host.ipaplatform.knownservices[
                    "NetworkManager"
                ].systemd_name,
            ],
            timeout=15,
        )

    def _make_state_from_args(self, nameservers, searchdomains):
        return {'nm_config': self.NM_CONF.format(
            nameservers=','.join(nameservers),
            searchdomains=','.join(searchdomains))}

    def _get_state(self):
        exists = self.host.transport.file_exists(self.NM_CONF_FILE)
        return {
            'nm_config':
                self.host.get_file_contents(self.NM_CONF_FILE, 'utf-8')
                if exists else None
        }

    def _apply_state(self, state):
        def get_resolv_conf_mtime():
            """Get mtime of /etc/resolv.conf.

            Returns mtime with sub-second precision as a string with format
            "2020-08-25 14:35:05.980503425 +0200"
            """
            return self.host.run_command(
                [
                    "stat",
                    "-c",
                    "%y",
                    self.host.ipaplatform.paths.RESOLV_CONF,
                ]
            ).stdout_text.strip()

        if state['nm_config'] is None:
            self.host.run_command(['rm', '-f', self.NM_CONF_FILE])
        else:
            self.host.run_command(
                ['mkdir', '-p', os.path.dirname(self.NM_CONF_FILE)])
            self.host.put_file_contents(
                self.NM_CONF_FILE, state['nm_config'])
        # NetworkManager writes /etc/resolv.conf few moments after
        # `systemctl restart` returns so we need to wait until the file is
        # updated
        mtime_before = get_resolv_conf_mtime()
        self._restart_network_manager()
        wait_until = time.time() + 10
        while time.time() < wait_until:
            if get_resolv_conf_mtime() != mtime_before:
                break
            time.sleep(1)
        else:
            raise Exception('NetworkManager did not update /etc/resolv.conf '
                            'in 10 seconds after restart')


def resolver(host):
    for cls in [ResolvedResolver, NetworkManagerResolver,
                PlainFileResolver]:
        if cls.is_our_resolver(host):
            logger.info('Detected DNS resolver manager for host %s is %s',
                        host.hostname, cls)
            return cls(host)
    raise Exception('Resolver manager could not be detected')
