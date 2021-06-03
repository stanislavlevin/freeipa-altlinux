#
# Copyright (C) 2019,2020  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests for Kerberos ticket policy options
"""

from __future__ import absolute_import

import pytest
import time
from datetime import datetime

from ipalib.constants import IPAAPI_USER

from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_otp import add_otptoken, del_otptoken
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.base_tasks import create_temp_file

PASSWORD = "Secret123"
USER1 = "testuser1"
USER2 = "testuser2"
MAXLIFE = 86400


def maxlife_within_policy(input, maxlife, slush=3600):
    """Given klist output of the TGT verify that it is within policy

       Ensure that the validity period is somewhere within the
       absolute maxlife and a slush value, maxlife - slush.

       Returns True if within policy.

       Input should be a string like:
       11/19/2019 16:37:40  11/20/2019 16:37:39  krbtgt/...

       slush defaults to 1 * 60 * 60 matching the jitter window.
    """
    data = input.split()
    start = datetime.strptime(data[0] + ' ' + data[1], '%m/%d/%Y %H:%M:%S')
    end = datetime.strptime(data[2] + ' ' + data[3], '%m/%d/%Y %H:%M:%S')
    diff = int((end - start).total_seconds())

    return maxlife >= diff >= maxlife - slush


@pytest.fixture
def reset_to_default_policy():
    """Reset default user authentication and user authentication type"""

    state = dict()

    def _reset_to_default_policy(host, user=None):
        state['host'] = host
        state['user'] = user

    yield _reset_to_default_policy

    host = state['host']
    user = state['user']
    tasks.kinit_admin(host)
    host.run_command(['ipa', 'krbtpolicy-reset'])
    if user:
        host.run_command(['ipa', 'user-mod', user, '--user-auth-type='])
        host.run_command(['ipa', 'krbtpolicy-reset', user])


def kinit_check_life(master, user):
    """Acquire a TGT and check if it's within the lifetime window"""
    master.run_command(["kinit", user], stdin_text=f"{PASSWORD}\n")
    result = master.run_command("klist | grep krbtgt")
    assert maxlife_within_policy(result.stdout_text, MAXLIFE) is True


class TestPWPolicy(IntegrationTest):
    """Tests password custom and default password policies.
    """
    num_replicas = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)
        tasks.create_active_user(cls.master, USER1, PASSWORD)
        tasks.create_active_user(cls.master, USER2, PASSWORD)

    @pytest.fixture(autouse=True, scope="function")
    def with_admin(self):
        tasks.kinit_admin(self.master)
        yield
        tasks.kdestroy_all(self.master)

    def test_krbtpolicy_default(self):
        """Test the default kerberos ticket policy 24-hr tickets"""
        master = self.master
        master.run_command(['ipa', 'krbtpolicy-mod', USER1,
                            '--maxlife', str(MAXLIFE)])
        tasks.kdestroy_all(master)

        master.run_command(['kinit', USER1],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, MAXLIFE) is True

    def test_krbtpolicy_hardended(self):
        """Test a hardened kerberos ticket policy with 10 min tickets"""
        master = self.master
        master.run_command(['ipa', 'user-mod', USER1,
                            '--user-auth-type', 'password',
                            '--user-auth-type', 'hardened'])
        master.run_command(['ipa', 'config-mod',
                            '--user-auth-type', 'password',
                            '--user-auth-type', 'hardened'])
        master.run_command(['ipa', 'krbtpolicy-mod', USER1,
                            '--hardened-maxlife', '600'])

        tasks.kdestroy_all(master)

        master.run_command(['kinit', USER1],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, 600,
                                     slush=600) is True

        tasks.kdestroy_all(master)

        # Verify that the short policy only applies to USER1
        master.run_command(['kinit', USER2],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, MAXLIFE) is True

    def test_krbtpolicy_password(self):
        """Test the kerberos ticket policy which issues 20 min tickets"""
        master = self.master
        master.run_command(['ipa', 'krbtpolicy-mod', USER2,
                            '--maxlife', '1200'])

        tasks.kdestroy_all(master)

        master.run_command(['kinit', USER2],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, 1200,
                                     slush=1200) is True

    def test_krbtpolicy_reset(self):
        """Test a hardened kerberos ticket policy reset"""
        master = self.master
        master.run_command(['ipa', 'krbtpolicy-reset', USER2])
        master.run_command(['kinit', USER2],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, MAXLIFE) is True

    def test_krbtpolicy_otp(self, reset_to_default_policy):
        """Test otp ticket policy"""
        master = self.master
        master.run_command(['ipa', 'user-mod', USER1,
                            '--user-auth-type', 'otp'])
        master.run_command(['ipa', 'config-mod',
                            '--user-auth-type', 'otp'])
        master.run_command(['ipa', 'krbtpolicy-mod', USER1,
                            '--otp-maxrenew=90', '--otp-maxlife=60'])
        armor = create_temp_file(self.master, create_file=False)
        otpuid, totp = add_otptoken(master, USER1, otptype="totp")
        otpvalue = totp.generate(int(time.time())).decode("ascii")
        reset_to_default_policy(master, USER1)
        try:
            tasks.kdestroy_all(master)
            # create armor for FAST
            master.run_command(['kinit', '-n', '-c', armor])
            # expect ticket expire in otp-maxlife=60 seconds
            master.run_command(
                ['kinit', '-T', armor, USER1, '-r', '90'],
                stdin_text='{0}{1}\n'.format(PASSWORD, otpvalue))
            master.run_command(['ipa', 'user-find', USER1])
            time.sleep(30)
            # when user kerberos ticket expired but still within renew time,
            #  kinit -R should give user new life
            master.run_command(['kinit', '-R', USER1])
            master.run_command(['ipa', 'user-find', USER1])
            time.sleep(60)
            # when renew time expires, kinit -R should fail
            result1 = master.run_command(['kinit', '-R', USER1],
                                         raiseonerr=False)
            tasks.assert_error(
                result1,
                "kinit: Ticket expired while renewing credentials", 1)
            master.run_command(['ipa', 'user-find', USER1],
                               ok_returncode=1)
        finally:
            del_otptoken(master, otpuid)
            self.master.run_command(['rm', '-f', armor])
            master.run_command(['ipa', 'config-mod', '--user-auth-type='])

    def test_krbtpolicy_jitter(self):
        """Test jitter lifetime with no auth indicators"""
        kinit_check_life(self.master, USER1)

    def test_krbtpolicy_jitter_otp(self, reset_to_default_policy):
        """Test jitter lifetime with OTP"""
        reset_to_default_policy(self.master, USER1)
        self.master.run_command(["ipa", "user-mod", USER1,
                                 "--user-auth-type", "otp"])
        kinit_check_life(self.master, USER1)

    def test_ccache_sweep_expired(self, reset_to_default_policy):
        """Test that the ccache sweeper works on expired ccaches

           - Force wipe all existing ccaches
           - Set the ticket policy to a short value, 20 seconds.
           - Do a series of kinit, ipa command, kdestroy to generate ccaches
           - sleep() for expiration
           - Run the sweeper
           - Verify that all expired ccaches are gone
        """
        MAXLIFE = 20
        reset_to_default_policy(self.master)  # this will reset at END of test
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ['ipa', 'krbtpolicy-mod', '--maxlife', str(MAXLIFE)]
        )
        tasks.kdestroy_all(self.master)
        self.master.run_command(
            [
                "find",
                self.master.ipaplatform.paths.IPA_CCACHES,
                "-type",
                "f",
                "-delete",
            ]
        )
        for _i in range(5):
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'user-show', 'admin'])
            tasks.kdestroy_all(self.master)

        result = self.master.run_command(
            "ls -1 {0} | wc -l".format(
                self.master.ipaplatform.paths.IPA_CCACHES
            )
        )
        assert int(result.stdout_text.strip()) == 5

        # let ccache expire
        time.sleep(MAXLIFE)
        ccache_sweep_cmd = ["/usr/libexec/ipa/ipa-ccache-sweeper", "-m", "0"]

        # should be run as ipaapi for GSSProxy
        self.master.run_command(
            ["runuser", "-u", IPAAPI_USER, "--"] + ccache_sweep_cmd
        )

        result = self.master.run_command(
            "ls -1 {0} | wc -l".format(
                self.master.ipaplatform.paths.IPA_CCACHES
            )
        )
        assert int(result.stdout_text.strip()) == 0

    def test_ccache_sweep_valid(self):
        """Test that the ccache sweeper doesn't remove valid ccaches
           - Force wipe all existing ccaches
           - Run the sweeper
           - Verify that all valid ccaches weren't removed
           Note: assumed that ccache expiration doesn't happen during test
        """
        tasks.kdestroy_all(self.master)
        self.master.run_command(
            [
                "find",
                self.master.ipaplatform.paths.IPA_CCACHES,
                "-type",
                "f",
                "-delete",
            ]
        )

        for _i in range(5):
            tasks.kinit_admin(self.master)
            self.master.run_command(["ipa", "user-show", "admin"])
            tasks.kdestroy_all(self.master)

        result = self.master.run_command(
            "ls -1 {0} | wc -l".format(
                self.master.ipaplatform.paths.IPA_CCACHES
            )
        )
        assert int(result.stdout_text.strip()) == 5

        ccache_sweep_cmd = ["/usr/libexec/ipa/ipa-ccache-sweeper", "-m", "0"]

        # should be run as ipaapi for GSSProxy
        self.master.run_command(
            ["runuser", "-u", IPAAPI_USER, "--"] + ccache_sweep_cmd
        )
        result = self.master.run_command(
            "ls -1 {0} | wc -l".format(
                self.master.ipaplatform.paths.IPA_CCACHES
            )
        )
        assert int(result.stdout_text.strip()) == 5
