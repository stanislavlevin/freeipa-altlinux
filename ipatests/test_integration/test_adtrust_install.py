#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""This module provides tests for ipa-adtrust-install utility"""

import re
import os
import textwrap

from ipapython.dn import DN
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestIpaAdTrustInstall(IntegrationTest):
    topology = 'line'
    num_replicas = 1

    def unconfigure_replica_as_agent(self, host):
        """ Remove a replica from the list of agents.

        cn=adtrust agents,cn=sysaccounts,cn=etc,$BASEDN contains a list
        of members representing the agents. Remove the replica principal
        from this list.
        This is a hack allowing to run multiple times
        ipa-adtrust-install --add-agents
        (otherwise if the replica is in the list of agents, it won't be seen
        as a possible agent to be added).
        """
        remove_agent_ldif = textwrap.dedent("""
             dn: cn=adtrust agents,cn=sysaccounts,cn=etc,{base_dn}
             changetype: modify
             delete: member
             member: fqdn={hostname},cn=computers,cn=accounts,{base_dn}
             """.format(base_dn=host.domain.basedn, hostname=host.hostname))
        # ok_returncode =16 if the attribute is not present
        tasks.ldapmodify_dm(self.master, remove_agent_ldif,
                            ok_returncode=[0, 16])

    def test_samba_config_file(self):
        """Check that ipa-adtrust-install generates sane smb.conf
        This is regression test for issue
        https://pagure.io/freeipa/issue/6951
        """
        self.master.run_command(
            ['ipa-adtrust-install', '-a', self.master.config.admin_password,
             '--add-sids', '-U'])
        res = self.master.run_command(['testparm', '-s'])
        assert 'ERROR' not in (res.stdout_text + res.stderr_text)

    def test_add_agent_not_allowed(self):
        """Check that add-agents can be run only by Admins."""
        user = "nonadmin"
        passwd = "Secret123"
        host = self.replicas[0].hostname
        data_fmt = '{{"method":"trust_enable_agent","params":[["{}"],{{}}]}}'

        try:
            # Create a nonadmin user that will be used by curl.
            # First, display SSSD kdcinfo:
            # https://bugzilla.redhat.com/show_bug.cgi?id=1850445#c1
            self.master.run_command([
                "cat",
                "/var/lib/sss/pubconf/kdcinfo.%s" % self.master.domain.realm
            ], raiseonerr=False)
            # Set krb5_trace to True: https://pagure.io/freeipa/issue/8353
            tasks.create_active_user(
                self.master, user, passwd, first=user, last=user,
                krb5_trace=True
            )
            tasks.kinit_as_user(self.master, user, passwd, krb5_trace=True)

            # curl --negotiate -u : is using GSS-API i.e. nonadmin user
            res = self.master.run_command(
                [
                    self.master.ipaplatform.paths.BIN_CURL,
                    "-H", "referer:https://{}/ipa".format(host),
                    "-H", "Content-Type:application/json",
                    "-H", "Accept:applicaton/json",
                    "--negotiate", "-u", ":",
                    "--cacert", self.master.ipaplatform.paths.IPA_CA_CRT,
                    "-d", data_fmt.format(host),
                    "-X", "POST", "https://{}/ipa/json".format(host),
                ]
            )
            expected = 'Insufficient access: not allowed to remotely add agent'
            assert expected in res.stdout_text
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'user-del', user])

    def test_add_agent_on_stopped_replica(self):
        """ Check ipa-adtrust-install --add-agents when the replica is stopped.

        Scenario: stop a replica
        Call ipa-adtrust-install --add-agents and configure the stopped replica
        as a new agent.
        The tool must detect that the replica is stopped and warn that
        a part of the configuration failed.

        Test for https://pagure.io/freeipa/issue/8148
        """
        self.unconfigure_replica_as_agent(self.replicas[0])
        self.replicas[0].run_command(['ipactl', 'stop'])

        try:
            cmd = ['ipa-adtrust-install', '--add-agents']
            with self.master.spawn_expect(cmd) as e:
                e.expect('admin password:')
                e.sendline(self.master.config.admin_password)
                # WARNING: The smb.conf already exists.
                # Running ipa-adtrust-install
                # will break your existing samba configuration.
                # Do you wish to continue? [no]:
                e.expect([
                    'smb\\.conf detected.+Overwrite smb\\.conf\\?',
                    'smb\\.conf already exists.+Do you wish to continue\\?'])
                e.sendline('yes')
                e.expect_exact('Enable trusted domains support in slapi-nis?')
                e.sendline('no')
                # WARNING: 1 IPA masters are not yet able to serve information
                # about users from trusted forests.
                # Installer can add them to the list of IPA masters allowed to
                # access information about trusts.
                # If you choose to do so, you also need to restart LDAP
                # service on
                # those masters.
                # Refer to ipa-adtrust-install(1) man page for details.
                # IPA master[replica1.testrelm.test]?[no]:
                e.expect('Installer can add them to the list of IPA masters '
                         'allowed to access information about trusts.+'
                         'IPA master \\[{}\\]'
                         .format(re.escape(self.replicas[0].hostname)),
                         timeout=120)
                e.sendline('yes')
                e.expect('"ipactl restart".+"systemctl restart sssd".+'
                         + re.escape(self.replicas[0].hostname),
                         timeout=60)
                e.expect_exit(ignore_remaining_output=True)
        finally:
            self.replicas[0].run_command(['ipactl', 'start'])

    def test_add_agent_on_running_replica_without_compat(self):
        """ Check ipa-adtrust-install --add-agents when the replica is running

        Scenario: replica up and running
        Call ipa-adtrust-install --add-agents and configure the replica as
        a new agent.
        The Schema Compat plugin must be automatically configured on the
        replica.
        """
        self.unconfigure_replica_as_agent(self.replicas[0])
        cmd = ['ipa-adtrust-install', '--add-agents']
        with self.master.spawn_expect(cmd) as e:
            e.expect_exact('admin password:')
            e.sendline(self.master.config.admin_password)
            # WARNING: The smb.conf already exists.
            # Running ipa-adtrust-install
            # will break your existing samba configuration.
            # Do you wish to continue? [no]:
            e.expect([
                'smb\\.conf detected.+Overwrite smb\\.conf\\?',
                'smb\\.conf already exists.+Do you wish to continue\\?'])
            e.sendline('yes')
            e.expect_exact('Enable trusted domains support in slapi-nis?')
            e.sendline('no')
            # WARNING: 1 IPA masters are not yet able to serve information
            # about users from trusted forests.
            # Installer can add them to the list of IPA masters allowed to
            # access information about trusts.
            # If you choose to do so, you also need to restart LDAP service on
            # those masters.
            # Refer to ipa-adtrust-install(1) man page for details.
            # IPA master[replica1.testrelm.test]?[no]:
            e.expect('Installer can add them to the list of IPA masters '
                     'allowed to access information about trusts.+'
                     'IPA master \\[{}\\]'
                     .format(re.escape(self.replicas[0].hostname)),
                     timeout=120)
            e.sendline('yes')
            e.expect_exit(ignore_remaining_output=True, timeout=60)
            output = e.get_last_output()
        assert 'Setup complete' in output
        # The replica must have been restarted automatically, no msg required
        assert 'ipactl restart' not in output

    def test_add_agent_on_running_replica_with_compat(self):
        """ Check ipa-addtrust-install --add-agents when the replica is running

        Scenario: replica up and running
        Call ipa-adtrust-install --add-agents --enable-compat and configure
        the replica as a new agent.
        The Schema Compat plugin must be automatically configured on the
        replica.
        """
        self.unconfigure_replica_as_agent(self.replicas[0])

        cmd = ['ipa-adtrust-install', '--add-agents', '--enable-compat']
        with self.master.spawn_expect(cmd) as e:
            e.expect_exact('admin password:')
            e.sendline(self.master.config.admin_password)
            # WARNING: The smb.conf already exists.
            # Running ipa-adtrust-install
            # will break your existing samba configuration.
            # Do you wish to continue? [no]:
            e.expect([
                'smb\\.conf detected.+Overwrite smb\\.conf\\?',
                'smb\\.conf already exists.+Do you wish to continue\\?'])
            e.sendline('yes')
            # WARNING: 1 IPA masters are not yet able to serve information
            # about users from trusted forests.
            # Installer can add them to the list of IPA masters allowed to
            # access information about trusts.
            # If you choose to do so, you also need to restart LDAP service on
            # those masters.
            # Refer to ipa-adtrust-install(1) man page for details.
            # IPA master[replica1.testrelm.test]?[no]:
            e.expect('Installer can add them to the list of IPA masters '
                     'allowed to access information about trusts.+'
                     'IPA master \\[{}\\]'
                     .format(re.escape(self.replicas[0].hostname)),
                     timeout=120)
            e.sendline('yes')
            e.expect_exit(ignore_remaining_output=True, timeout=60)
            output = e.get_last_output()
        assert 'Setup complete' in output
        # The replica must have been restarted automatically, no msg required
        assert 'ipactl restart' not in output

        # Ensure that the schema compat plugin is configured:
        conn = self.replicas[0].ldap_connect()
        entry = conn.get_entry(DN(
            "cn=users,cn=Schema Compatibility,cn=plugins,cn=config"))
        assert entry.single_value['schema-compat-lookup-nsswitch'] == "user"
        entry = conn.get_entry(DN(
            "cn=groups,cn=Schema Compatibility,cn=plugins,cn=config"))
        assert entry.single_value['schema-compat-lookup-nsswitch'] == "group"

    def test_schema_compat_attribute(self):
        """Test if schema-compat-entry-attribute is set

        This is to ensure if said entry is set after installation with AD.

        related: https://pagure.io/freeipa/issue/8193
        """
        conn = self.replicas[0].ldap_connect()
        entry = conn.get_entry(DN(
            "cn=groups,cn=Schema Compatibility,cn=plugins,cn=config"))
        entry_list = list(entry['schema-compat-entry-attribute'])
        value = (r'ipaexternalmember=%deref_r('
                 '"member","ipaexternalmember")')
        assert value in entry_list

    def test_ipa_user_pac(self):
        """Test that a user can request a service ticket with PAC"""
        user = 'testpacuser'
        user_princ = '@'.join([user, self.master.domain.realm])
        passwd = 'Secret123'
        # Create a user with a password
        tasks.create_active_user(self.master, user, passwd, extra_args=[
            '--homedir', '/home/{}'.format(user)])
        try:
            # Defaults: host/... principal for service
            # keytab in /etc/krb5.keytab
            self.master.run_command(["kinit", '-k'])
            # Don't use enterprise principal here because it doesn't work
            # bug in krb5: src/lib/gssapi/krb5/acquire_cred.c:scan_cache()
            # where enterprise principals aren't taken into account
            result = self.master.run_command(
                [
                    os.path.join(
                        self.master.ipaplatform.paths.LIBEXEC_IPA_DIR,
                        "ipa-print-pac",
                    ),
                    "ticket",
                    user_princ,
                ],
                stdin_text=(passwd + '\n'), raiseonerr=False
            )
            assert "PAC_DATA" in result.stdout_text
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'user-del', user])

    def test_ipa_user_s4u2self_pac(self):
        """Test that a service can request S4U2Self ticket with PAC"""
        user = 'tests4u2selfuser'
        user_princ = '@'.join([user, self.master.domain.realm])
        passwd = 'Secret123'
        # Create a user with a password
        tasks.create_active_user(self.master, user, passwd, extra_args=[
            '--homedir', '/home/{}'.format(user)])
        try:
            # Defaults: host/... principal for service
            # keytab in /etc/krb5.keytab
            self.master.run_command(["kinit", '-k'])
            result = self.master.run_command(
                [
                    os.path.join(
                        self.master.ipaplatform.paths.LIBEXEC_IPA_DIR,
                        "ipa-print-pac",
                    ),
                    "-E",
                    "impersonate",
                    user_princ,
                ],
                raiseonerr=False,
            )
            assert "PAC_DATA" in result.stdout_text
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'user-del', user])
