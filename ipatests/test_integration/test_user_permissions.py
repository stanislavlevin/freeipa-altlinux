#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

class TestUserPermissions(IntegrationTest):
    topology = 'star'
    altadmin = "altadmin"

    @classmethod
    def install(cls, mh):
        super(TestUserPermissions, cls).install(mh)
        tasks.kinit_admin(cls.master)

        # Create a new user altadmin
        password_confirmation = "%s\n%s\n" % (cls.master.config.admin_password,
                                              cls.master.config.admin_password)
        cls.master.run_command(['ipa', 'user-add', cls.altadmin,
                                '--first', cls.altadmin,
                                '--last', cls.altadmin,
                                '--password'],
                               stdin_text=password_confirmation)

        # Add altadmin to the group cn=admins
        cls.master.run_command(['ipa', 'group-add-member', 'admins',
                                '--users', cls.altadmin])

        # kinit as altadmin to initialize the password
        altadmin_kinit = "%s\n%s\n%s\n" % (cls.master.config.admin_password,
                                           cls.master.config.admin_password,
                                           cls.master.config.admin_password)
        cls.master.run_command(['kinit', cls.altadmin],
                               stdin_text=altadmin_kinit)
        cls.master.run_command(['kdestroy', '-A'])

    def test_delete_preserve_as_alternate_admin(self):
        """
        Test that a user member of admins group can call delete --preserve.

        This is a test case for issue 7342
        """

        # kinit admin
        tasks.kinit_admin(self.master)

        # Create a new user 'testuser' with a password
        testuser = 'testuser'
        password = 'Secret123'
        testuser_password_confirmation = "%s\n%s\n" % (password,
                                                       password)
        self.master.run_command(['ipa', 'user-add', testuser,
                                 '--first', testuser,
                                 '--last', testuser,
                                 '--password'],
                                stdin_text=testuser_password_confirmation)

        # kinit as altadmin
        self.master.run_command(['kinit', self.altadmin],
                                stdin_text=self.master.config.admin_password)

        # call ipa user-del --preserve
        self.master.run_command(['ipa', 'user-del', '--preserve', testuser])

    @pytest.mark.skip_if_not_hostselinux(
        "master", reason="Test needs SELinux enabled"
    )
    def test_selinux_user_optimized(self):
        """
        Check that SELinux login context is set on first login for the
        user, even if the user is not mapped to a specific SELinux user.

        Related ticket https://pagure.io/SSSD/sssd/issue/3819.
        """

        # Scenario: add an IPA user with non-default home dir, login through
        # ssh as this user and check that there is a SELinux user mapping
        # for the user with `semanage login -l`.

        test_user = 'testuser_selinux'
        password = 'Secret123'

        tasks.kinit_admin(self.master)
        tasks.create_active_user(
            self.master, test_user, password=password,
            extra_args=['--homedir', '/root/{}'.format(test_user)]
        )

        tasks.run_ssh_cmd(
            to_host=self.master.external_hostname, username=test_user,
            auth_method="password", password=password
        )

        # check if user listed in output
        cmd = self.master.run_command(['semanage', 'login', '-l'])
        assert test_user in cmd.stdout_text

        # call ipa user-del
        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'user-del', test_user])

    def test_stageuser_show_as_alternate_admin(self):
        """
        Test that a user member of admins group can call stageuser-show
        and read the 'Kerberos Keys available' information.

        This is a test case for issue 7342
        """
        # kinit admin
        tasks.kinit_admin(self.master)

        # Create a new stage user 'stageuser' with a password
        stageuser = 'stageuser'
        password = 'Secret123'
        stageuser_password_confirmation = "%s\n%s\n" % (password,
                                                        password)
        self.master.run_command(['ipa', 'stageuser-add', stageuser,
                                 '--first', stageuser,
                                 '--last', stageuser,
                                 '--password'],
                                stdin_text=stageuser_password_confirmation)

        # kinit as altadmin
        self.master.run_command(['kinit', self.altadmin],
                                stdin_text=self.master.config.admin_password)

        # call ipa stageuser-show
        # the field Kerberos Keys available must contain True
        result = self.master.run_command(['ipa', 'stageuser-show', stageuser])
        assert 'Kerberos keys available: True' in result.stdout_text

    def test_user_add_withradius(self):
        """
        Test that a user with User Administrator role can call
        ipa user-add --radius myradius
        to create a user with an assigned Radius Proxy Server.

        This is a test case for issue 7570
        """
        # kinit admin
        tasks.kinit_admin(self.master)

        # Create a radius proxy server
        radiusproxy = 'myradius'
        secret = 'Secret123'
        radius_secret_confirmation = "%s\n%s\n" % (secret, secret)
        self.master.run_command(
            ['ipa', 'radiusproxy-add', radiusproxy,
             '--server', 'radius.example.com', '--secret'],
            stdin_text=radius_secret_confirmation)

        # Create a user with 'User Administrator' role
        altuser = 'specialuser'
        password = 'SpecialUser123'
        password_confirmation = "%s\n%s\n" % (password, password)
        self.master.run_command(
            ['ipa', 'user-add', altuser, '--first', altuser, '--last', altuser,
             '--password'],
            stdin_text=password_confirmation)
        self.master.run_command(
            ['ipa', 'role-add-member', "User Administrator",
             '--user', altuser])

        # kinit as altuser to initialize the password
        altuser_kinit = "%s\n%s\n%s\n" % (password, password, password)
        self.master.run_command(['kinit', altuser], stdin_text=altuser_kinit)
        # call ipa user-add with --radius=...
        # this call requires read access to radius proxy servers
        self.master.run_command(
            ['ipa', 'user-add', '--first', 'test', '--last', 'test',
             '--user-auth-type', 'radius', '--radius-username', 'testradius',
             'testradius', '--radius', radiusproxy])

    def test_delete_group_by_user_administrator(self):
        """
        Test that a user with sufficient privileges can delete group
        This is a Automation for issue 6884
        """
        # Create a new testadmin user with a password
        testadmin = 'tuser'
        password = 'Secret123'
        testgroup = 'gtest'

        try:
            tasks.create_active_user(self.master, testadmin, password)

            # Add testadmin user to role "User Administrator"
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'role-add-member',
                                     '--users', testadmin,
                                     'User Administrator'])
            tasks.kdestroy_all(self.master)

            # Create a test group
            tasks.kinit_as_user(self.master, testadmin, password)
            self.master.run_command(['ipa', 'group-add', testgroup])

            # Call ipa-group-del to check if user can delete group
            self.master.run_command(['ipa', 'group-del', testgroup])
        finally:
            # Cleanup
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'user-del', testadmin])
            self.master.run_command(['ipa', 'group-del', testgroup,
                                     '--continue'])


class TestInstallClientNoAdmin(IntegrationTest):
    num_clients = 1

    def test_installclient_as_user_admin(self):
        """ipa-client-install should not use hardcoded admin for principal

        In ipaclient-install.log it should use the username that was entered
        earlier in the install process at the prompt.
        Related to : https://pagure.io/freeipa/issue/5406
        """
        client = self.clients[0]
        tasks.install_master(self.master)
        tasks.kinit_admin(self.master)
        username = 'testuser1'
        password = 'userSecretPassword123'
        password_confirmation = "%s\n%s\n" % (password,
                                              password)

        self.master.run_command(['ipa', 'user-add', username,
                                 '--first', username,
                                 '--last', username,
                                 '--password'],
                                stdin_text=password_confirmation)

        role_add = ['ipa', 'role-add', 'useradmin']
        self.master.run_command(role_add)
        self.master.run_command(['ipa', 'privilege-add', 'Add Hosts'])
        self.master.run_command(['ipa', 'privilege-add-permission',
                                 '--permissions', 'System: Add Hosts',
                                 'Add Hosts'])

        self.master.run_command(['ipa', 'role-add-privilege', 'useradmin',
                                 '--privileges', 'Host Enrollment'])

        self.master.run_command(['ipa', 'role-add-privilege', 'useradmin',
                                 '--privileges', 'Add Hosts'])

        role_member_add = ['ipa', 'role-add-member', 'useradmin',
                           '--users={}'.format(username)]
        self.master.run_command(role_member_add)
        user_kinit = "%s\n%s\n%s\n" % (password, password, password)
        self.master.run_command(['kinit', username],
                                stdin_text=user_kinit)
        tasks.install_client(
            self.master, client,
            extra_args=['--request-cert'],
            user=username, password=password
        )
        msg = "args=['/usr/bin/getent', 'passwd', '%s@%s']" % \
              (username, client.domain.name)
        install_log = client.get_file_contents(
            client.ipaplatform.paths.IPACLIENT_INSTALL_LOG, encoding="utf-8"
        )
        assert msg in install_log

        # check that user is able to request a host cert, too
        result = tasks.run_certutil(
            client, ['-L'], client.ipaplatform.paths.IPA_NSSDB_DIR
        )
        assert 'Local IPA host' in result.stdout_text
        result = tasks.run_certutil(
            client,
            ["-K", "-f", client.ipaplatform.paths.IPA_NSSDB_PWDFILE_TXT],
            client.ipaplatform.paths.IPA_NSSDB_DIR,
        )
        assert 'Local IPA host' in result.stdout_text
