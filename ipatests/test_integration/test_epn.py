#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

######
# This test suite will _expectedly_ fail if run at the end of the UTC day
# because users would be created during day N and then EPN output checked
# during day N+1. This is expected and should be ignored as it does not
# reflect a product bug. -- fcami
######

from __future__ import print_function, absolute_import

import base64
import datetime
import email
import json
import logging
import os
import pytest
import re
import textwrap

from subprocess import CalledProcessError

from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

logger = logging.getLogger(__name__)

EPN_PKG = ["*ipa-client-epn"]

SASLAUTHD_SYSCONFIG_PATH = "/etc/sysconfig/saslauthd"
SASLAUTHD_RUNDIR = "/var/spool/postfix/var/run/saslauthd"
POSTFIX_SASL_CONF = "/etc/postfix/sasl/smtpd.conf"
POSTFIX_MASTER_CONF = "/etc/postfix/master.cf"

DEFAULT_EPN_CONF = textwrap.dedent(
    """\
    [global]
    """
)

USER_EPN_CONF = DEFAULT_EPN_CONF + textwrap.dedent(
    """\
    smtp_user={user}
    smtp_password={password}
    """
)

STARTTLS_EPN_CONF = USER_EPN_CONF + textwrap.dedent(
    """\
    smtp_server={server}
    smtp_security=starttls
    """
)

SSL_EPN_CONF = USER_EPN_CONF + textwrap.dedent(
    """\
    smtp_server={server}
    smtp_port=465
    smtp_security=ssl
    """
)


def datetime_to_generalized_time(dt):
    """Convert datetime to LDAP_GENERALIZED_TIME_FORMAT
       Note: Move into ipalib.
    """
    dt = dt.timetuple()
    generalized_time_str = str(dt.tm_year) + "".join(
        "0" * (2 - len(str(item))) + str(item)
        for item in (dt.tm_mon, dt.tm_mday, dt.tm_hour, dt.tm_min, dt.tm_sec,)
    )
    return generalized_time_str + "Z"


def postconf(host, option):
    host.run_command(r"postconf -e '%s'" % option)


def configure_postfix(host, realm):
    """Configure postfix for:
          * SASL auth
          * to be the destination of the IPA domain.
    """
    # first, shutdown services
    services = ["saslauthd", "postfix"]
    for service in services:
        host.run_command(["systemctl", "stop", service])

    # Setup the keytab we need for SASL auth
    host.run_command(
        ["ipa", "service-add", "smtp/%s" % host.hostname, "--force"]
    )
    host.run_command(r"ipa-getkeytab -p smtp/%s -k /etc/postfix/smtp.keytab" %
                     host.hostname)
    # alt-specific
    host.run_command(r"chmod 600 /etc/postfix/smtp.keytab")

    # Enable Postfix SMTP service without content filter
    host.run_command(["control", "postfix", "server"])

    # Configure the SASL smtp service to use GSSAPI
    host.run_command(["mkdir", "/etc/postfix/sasl"])
    postfix_sasl = textwrap.dedent(
        """\
        pwcheck_method: saslauthd
        mech_list: plain login
        """
    )
    host.put_file_contents(POSTFIX_SASL_CONF, postfix_sasl)

    # set kerberos5 mech and point to chrooted postfix
    # alt's postfix lives in chroot, let's pass down saslauthd socket into it
    saslauthd_sys_conf = host.get_file_contents(
        SASLAUTHD_SYSCONFIG_PATH, encoding="utf-8"
    )
    saslauthd_sys_conf = re.sub(
        r"^OPTIONS=.*",
        f"OPTIONS='-a kerberos5 -n 0 -m {SASLAUTHD_RUNDIR}'",
        saslauthd_sys_conf
    )
    host.put_file_contents(SASLAUTHD_SYSCONFIG_PATH, saslauthd_sys_conf)

    host.run_command(["mkdir", "-p", "/etc/systemd/system/saslauthd.service.d"])
    saslauthd_conf_path = "/etc/systemd/system/saslauthd.service.d/custom.conf"
    saslauthd_conf = textwrap.dedent(
        """\
        [Service]
        PIDFile={}/saslauthd.pid
        """
    ).format(SASLAUTHD_RUNDIR)
    host.put_file_contents(saslauthd_conf_path, saslauthd_conf)
    host.run_command(["systemctl", "daemon-reload"])

    host.run_command(["mkdir", "-p", SASLAUTHD_RUNDIR])
    host.run_command(["chown", "postfix:root", "/var/spool/postfix/var"])
    host.run_command(["chmod", "0750", "/var/spool/postfix/var"])

    # alt-only option
    postconf(host, "mailbox_unpriv_delivery = no")

    # end of alt-specific

    postconf(host,
             'import_environment = MAIL_CONFIG MAIL_DEBUG MAIL_LOGTAG TZ '
             'XAUTHORITY DISPLAY LANG=C KRB5_KTNAME=/etc/postfix/smtp.keytab')
    postconf(host,
             'smtpd_client_restrictions = permit_sasl_authenticated, reject')
    postconf(host,
             'smtpd_recipient_restrictions = permit_sasl_authenticated, reject')
    postconf(host,
             'smtpd_sender_restrictions = permit_sasl_authenticated, reject')
    postconf(host, 'smtpd_sasl_auth_enable = yes')
    postconf(host, 'smtpd_sasl_security_options = noanonymous')
    postconf(host,
             'smtpd_sasl_tls_security_options = $smtpd_sasl_security_options')
    postconf(host, 'broken_sasl_auth_clients = yes')
    postconf(host, 'smtpd_sasl_authenticated_header = yes')
    postconf(host, 'smtpd_sasl_local_domain = %s' % realm)
    # TLS will not be used
    postconf(host, 'smtpd_tls_security_level = none')

    # disable procmail if exists, make use of default local(8) delivery agent
    postconf(host, "mailbox_command=")

    host.run_command(["systemctl", "restart", "saslauthd"])

    result = host.run_command(["postconf", "mydestination"])
    mydestination = result.stdout_text.strip() + ", " + host.domain.name
    postconf(host, mydestination)

    host.run_command(["systemctl", "restart", "postfix"])


def configure_starttls(host):
    """Obtain a TLS cert for the host and configure postfix for starttls

       Depends on configure_postfix() being executed first.
    """

    host.run_command(
        [
            "rm", "-f", os.path.join(paths.OPENSSL_PRIVATE_DIR, "postfix.key"),
        ]
    )
    host.run_command(
        [
            "rm",
            "-f",
            os.path.join(paths.OPENSSL_CERTS_DIR, "postfix.pem"),
        ]
    )
    host.run_command(["ipa-getcert", "request",
                      "-f",
                      os.path.join(paths.OPENSSL_CERTS_DIR, "postfix.pem"),
                      "-k",
                      os.path.join(paths.OPENSSL_PRIVATE_DIR, "postfix.key"),
                      "-K", "smtp/%s" % host.hostname,
                      "-D", host.hostname,
                      "-O", "postfix",
                      "-o", "postfix",
                      "-M", "0640",
                      "-m", "0640",
                      "-w",
                      ])
    postconf(host, 'smtpd_tls_loglevel = 1')
    postconf(host, 'smtpd_tls_auth_only = yes')
    postconf(
        host,
        "smtpd_tls_key_file = {}".format(
            os.path.join(paths.OPENSSL_PRIVATE_DIR, "postfix.key")
        )
    )
    postconf(
        host,
        "smtpd_tls_cert_file = {}".format(
            os.path.join(paths.OPENSSL_CERTS_DIR, "postfix.pem")
        )
    )
    postconf(host, 'smtpd_tls_received_header = yes')
    postconf(host, 'smtpd_tls_session_cache_timeout = 3600s')
    # announce STARTTLS support to remote SMTP clients, not require
    postconf(host, 'smtpd_tls_security_level = may')

    host.run_command(["systemctl", "restart", "postfix"])


def configure_ssl(host):
    """Enable the ssl listener on port 465.
    """
    conf = host.get_file_contents(POSTFIX_MASTER_CONF, encoding='utf-8')
    # put postfix into chroot(5th field)
    conf += 'smtps inet n - - - - smtpd\n'
    conf += '  -o syslog_name=postfix/smtps\n'
    conf += '  -o smtpd_tls_wrappermode=yes\n'
    conf += '  -o smtpd_sasl_auth_enable=yes\n'
    host.put_file_contents(POSTFIX_MASTER_CONF, conf)

    host.run_command(["systemctl", "restart", "postfix"])


def decode_header(header):
    """Decode the header if needed and return the value"""
    # Only support one value for now
    (value, encoding) = email.header.decode_header(header)[0]
    if encoding:
        return value.decode(encoding)
    else:
        return value


def validate_mail(host, id, content):
    """Retrieve a remote e-mail and determine if it matches the current user"""
    mail = host.get_file_contents('/var/mail/user%d' % id)
    msg = email.message_from_bytes(mail)
    assert decode_header(msg['To']) == 'user%d@%s' % (id, host.domain.name)
    assert decode_header(msg['From']) == 'IPA-EPN <noreply@%s>' % \
                                         host.domain.name
    assert decode_header(msg['subject']) == 'Your password will expire soon.'

    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        body = part.get_payload()
        decoded = base64.b64decode(body).decode('utf-8')
        assert content in decoded


class TestEPN(IntegrationTest):
    """Test Suite for EPN: https://pagure.io/freeipa/issue/3687
    """

    num_clients = 1
    notify_ttls = (28, 14, 7, 3, 1)

    def _check_epn_output(
        self,
        host,
        dry_run=False,
        mailtest=False,
        from_nbdays=None,
        to_nbdays=None,
        raiseonerr=True,
        validatejson=True
    ):
        result = tasks.ipa_epn(
            host,
            from_nbdays=from_nbdays,
            to_nbdays=to_nbdays,
            mailtest=mailtest,
            dry_run=dry_run,
            raiseonerr=raiseonerr
        )
        if validatejson:
            json.dumps(json.loads(result.stdout_text), ensure_ascii=False)
        return (result.stdout_text, result.stderr_text, result.returncode)

    @classmethod
    def install(cls, mh):
        # External DNS is only available before install so cache a copy
        # of the *ipa-epn-client package so we can experimentally remove
        # it later.
        #
        # Notes:
        # - A package can't be downloaded that is already installed so we
        #   have to remove it first.
        # - dnf cleans up previously downloaded locations so make a copy it
        #   doesn't know about.
        # - Adds a class variable, pkg, containing the package name of
        #   the downloaded *ipa-client-epn rpm.
        cls.pkg = None
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_client(cls.master, cls.clients[0])

        tasks.install_packages(cls.master, ["postfix"])
        tasks.install_packages(cls.clients[0], ["postfix"])
        for host in (cls.master, cls.clients[0]):
            platform = tasks.get_platform(host)
            cyrus_sasl_packages = ["cyrus-sasl"]

            if platform in ("altlinux"):
                cyrus_sasl_packages = [
                    "cyrus-sasl2", "postfix-cyrus", "postfix-tls",
                ]
            try:
                tasks.install_packages(host, cyrus_sasl_packages)
            except Exception:
                # the package is likely already installed
                pass
        configure_postfix(cls.master, cls.master.domain.realm)
        configure_postfix(cls.clients[0], cls.master.domain.realm)

    @classmethod
    def uninstall(cls, mh):
        services = ["saslauthd", "postfix"]
        for host in [cls.master, cls.clients[0]]:
            for service in services:
                host.run_command(["systemctl", "stop", service])

            host.run_command(
                ["ipa", "service-del", "smtp/%s" % host.hostname],
                raiseonerr=False,
            )

        tasks.uninstall_packages(cls.master, ["postfix"])
        tasks.uninstall_packages(cls.clients[0], ["postfix"])
        cls.master.run_command(r'rm -f /etc/postfix/smtp.keytab')
        super(TestEPN, cls).uninstall(mh)
        cls.master.run_command(
            [
                "getcert",
                "stop-tracking",
                "-f",
                os.path.join(paths.OPENSSL_CERTS_DIR, "postfix.pem"),
            ]
        )
        to_remove = [
            os.path.join(paths.OPENSSL_PRIVATE_DIR, "postfix.key"),
            os.path.join(paths.OPENSSL_CERTS_DIR, "postfix.pem"),
            "/etc/systemd/system/saslauthd.service.d/custom.conf",
            "/etc/postfix/sasl",
            SASLAUTHD_RUNDIR,
        ]

        cmd = ["rm", "-rf"]
        cmd.extend(to_remove)
        cls.master.run_command(cmd)

    @pytest.mark.skip_if_platform(
        "debian", reason="Cannot check installed packages using RPM"
    )
    @pytest.mark.skip_if_platform(
        "altlinux", reason="Fedora/RHEL specific"
    )
    def test_EPN_config_file(self):
        """Check that the EPN configuration file is installed.
           https://pagure.io/freeipa/issue/8374
        """
        epn_conf = "/etc/ipa/epn.conf"
        epn_template = "/etc/ipa/epn/expire_msg.template"
        if tasks.get_platform(self.master) != "fedora":
            cmd1 = self.master.run_command(["rpm", "-qc", "ipa-client-epn"])
        else:
            cmd1 = self.master.run_command(["rpm", "-qc", "freeipa-client-epn"])
        assert epn_conf in cmd1.stdout_text
        assert epn_template in cmd1.stdout_text
        cmd2 = self.master.run_command(["sha256sum", epn_conf])
        ck = "192481b52fb591112afd7b55b12a44c6618fdbc7e05a3b1866fd67ec579c51df"
        assert cmd2.stdout_text.find(ck) == 0

    def test_EPN_connection_refused(self):
        """Test EPN behavior when the configured SMTP is down
        """

        self.master.run_command(["systemctl", "stop", "postfix"])
        (unused, stderr_text, rc) = self._check_epn_output(
            self.master, mailtest=True,
            raiseonerr=False, validatejson=False
        )
        self.master.run_command(["systemctl", "start", "postfix"])
        assert "IPA-EPN: Could not connect to the configured SMTP server" in \
            stderr_text
        assert rc > 0

    def test_EPN_no_security_downgrade_starttls(self):
        """Configure postfix without starttls and test no auth happens
        """
        epn_conf = STARTTLS_EPN_CONF.format(
            server=self.master.hostname,
            user=self.master.config.admin_name,
            password=self.master.config.admin_password,
        )
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)

        (unused, stderr_text, rc) = self._check_epn_output(
            self.master, mailtest=True,
            raiseonerr=False, validatejson=False
        )
        expected_msg = "IPA-EPN: Unable to create an encrypted session to"
        assert expected_msg in stderr_text
        assert rc > 0

    def test_EPN_no_security_downgrade_tls(self):
        """Configure postfix without tls and test no auth happens
        """
        epn_conf = SSL_EPN_CONF.format(
            server=self.master.hostname,
            user=self.master.config.admin_name,
            password=self.master.config.admin_password,
        )
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)

        (unused, stderr_text, rc) = self._check_epn_output(
            self.master, mailtest=True,
            raiseonerr=False, validatejson=False
        )
        expected_msg = (
            "IPA-EPN: Could not connect to the configured SMTP "
            "server"
        )
        assert expected_msg in stderr_text
        assert rc > 0

    def test_EPN_smoketest_1(self):
        """No users except admin. Check --dry-run output.
           With the default configuration, the result should be an empty list.
           Also check behavior on master and client alike.
        """
        self.master.put_file_contents('/etc/ipa/epn.conf', DEFAULT_EPN_CONF)
        # check EPN on client (LDAP+GSSAPI)
        (stdout_text, unused, _unused) = self._check_epn_output(
            self.clients[0], dry_run=True
        )
        assert len(json.loads(stdout_text)) == 0
        # check EPN on master (LDAPI)
        (stdout_text, unused, _unused) = self._check_epn_output(
            self.master, dry_run=True
        )
        assert len(json.loads(stdout_text)) == 0

    @pytest.fixture
    def cleanupusers(self):
        """Fixture to remove any users added as part of the tests.

           It isn't necessary to remove all users created.

           Ignore all errors.
        """
        yield
        for user in ["testuser0", "testuser1"]:
            try:
                self.master.run_command(['ipa', 'user-del', user])
            except Exception:
                pass

    @pytest.fixture
    def cleanupmail(self):
        """Cleanup any existing mail that has been sent."""
        cmd = ["rm", "-f"]
        for i in range(30):
            cmd.append("/var/mail/user%d" % i)
        self.master.run_command(cmd)

    def test_EPN_smoketest_2(self, cleanupusers):
        """Add a user without password.
           Add a user whose password expires within the default time range.
           Check --dry-run output.
        """
        tasks.user_add(self.master, "testuser0")
        tasks.user_add(
            self.master,
            "testuser1",
            password="Secret123",
            extra_args=[
                "--password-expiration",
                datetime_to_generalized_time(
                    datetime.datetime.utcnow() + datetime.timedelta(days=7)
                ),
            ],
        )
        (stdout_text_client, unused, _unused) = self._check_epn_output(
            self.clients[0], dry_run=True
        )
        (stdout_text_master, unused, _unused) = self._check_epn_output(
            self.master, dry_run=True
        )
        assert stdout_text_master == stdout_text_client
        assert "testuser0" not in stdout_text_client
        assert "testuser1" in stdout_text_client

    def test_EPN_smoketest_3(self):
        """Add a bunch of users with incrementally expiring passwords
           (one per day). Check --dry-run output.
        """

        users = {}
        userbase_str = "user"

        for i in range(30):
            uid = userbase_str + str(i)
            users[i] = dict(
                uid=uid,
                days=i,
                krbpasswordexpiration=datetime_to_generalized_time(
                    datetime.datetime.utcnow() + datetime.timedelta(days=i)
                ),
            )

        for key in users:
            tasks.user_add(
                self.master,
                users[key]["uid"],
                extra_args=[
                    "--password-expiration",
                    users[key]["krbpasswordexpiration"],
                ],
                password=None,
            )

        (stdout_text_client, unused, _unused) = self._check_epn_output(
            self.clients[0], dry_run=True
        )
        (stdout_text_master, unused, _unused) = self._check_epn_output(
            self.master, dry_run=True
        )
        assert stdout_text_master == stdout_text_client
        user_lst = []
        for user in json.loads(stdout_text_master):
            user_lst.append(user["uid"])
        expected_users = ["user1", "user3", "user7", "user14", "user28"]
        assert sorted(user_lst) == sorted(expected_users)

    def test_EPN_nbdays_0(self, cleanupmail):
        """Test the to/from nbdays options (implies --dry-run)

           We have a set of users installed with varying expiration
           dates. Confirm that to/from nbdays finds them.

           Make sure --dry-run does not accidentally send emails.
        """

        # Use the notify_ttls values with a 1-day sliding window
        for i in self.notify_ttls:
            user_list = []
            (stdout_text_client, unused, _unused) = self._check_epn_output(
                self.clients[0], from_nbdays=i, to_nbdays=i + 1, dry_run=True
            )
            for user in json.loads(stdout_text_client):
                user_list.append(user["uid"])
            assert len(user_list) == 1
            userid = "user{id}".format(id=i)
            assert user_list[0] == userid

            # Check that the user list is expected for any given notify_ttls.
            (stdout_text_client, unused, _unused) = self._check_epn_output(
                self.clients[0], to_nbdays=i
            )
            user_list = [user["uid"] for user in json.loads(stdout_text_client)]
            assert len(user_list) == 1
            assert user_list[0] == "user{id}".format(id=i - 1)

            # make sure no emails were sent
            result = self.clients[0].run_command(['ls', '-lha', '/var/mail/'])
            assert userid not in result.stdout_text

    def test_EPN_nbdays_1(self, cleanupmail):
        """Test that for a given range, we find the users in that range"""

        # Use hardcoded date ranges for now
        for date_range in [(0, 5), (7, 15), (1, 20)]:
            expected_user_list = ["user{i}".format(i=i)
                                  for i in range(date_range[0], date_range[1])]
            (stdout_text_client, unused, _unused) = self._check_epn_output(
                self.clients[0],
                from_nbdays=date_range[0],
                to_nbdays=date_range[1]
            )
            user_list = [user["uid"] for user in json.loads(stdout_text_client)]
            for user in expected_user_list:
                assert user in user_list
            for user in user_list:
                assert user in expected_user_list

    # Test the to/from nbdays options behavior with illegal input

    def test_EPN_nbdays_input_0(self):
        """Make sure that --to-nbdays implies --dry-run ;
           therefore check that the output is valid JSON and contains the
           expected user.
        """

        (stdout_text_client, unused, _unused) = self._check_epn_output(
            self.clients[0], to_nbdays=5, dry_run=False
        )
        assert len(json.loads(stdout_text_client)) == 1
        assert json.loads(stdout_text_client)[0]["uid"] == "user4"

    def test_EPN_nbdays_input_1(self):
        """Make sure that --from-nbdays cannot be used without --to-nbdays"""

        (unused, stderr_text_client, rc) = \
            self._check_epn_output(
            self.clients[0], from_nbdays=3,
            raiseonerr=False, validatejson=False
        )
        assert "You cannot specify --from-nbdays without --to-nbdays" \
            in stderr_text_client
        assert rc > 0

    def test_EPN_nbdays_input_2(self):
        """alpha input"""

        (unused, stderr, rc) = self._check_epn_output(
            self.clients[0], to_nbdays="abc",
            raiseonerr=False, validatejson=False
        )
        assert "error: --to-nbdays must be a positive integer." in stderr
        assert rc > 0

    def test_EPN_nbdays_input_3(self):
        """from_nbdays > to_nbdays"""

        (unused, stderr, rc) = self._check_epn_output(
            self.clients[0], from_nbdays=9, to_nbdays=7,
            raiseonerr=False, validatejson=False
        )
        assert "error: --from-nbdays must be smaller than --to-nbdays." in \
            stderr
        assert rc > 0

    def test_EPN_nbdays_input_4(self):
        """decimal input"""

        (unused, stderr, rc) = self._check_epn_output(
            self.clients[0], to_nbdays=7.3,
            raiseonerr=False, validatejson=False
        )
        logger.info(stderr)
        assert rc > 0
        assert "error: --to-nbdays must be a positive integer." in stderr

    # From here the tests build on one another:
    #  1) add auth
    #  2) tweak the template
    #  3) add starttls

    def test_EPN_authenticated(self, cleanupmail):
        """Enable authentication and test that mail is delivered
        """
        epn_conf = USER_EPN_CONF.format(
            user=self.master.config.admin_name,
            password=self.master.config.admin_password,
        )
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)

        tasks.ipa_epn(self.master)
        for i in self.notify_ttls:
            validate_mail(self.master, i,
                          "Hi test user,\n\nYour password will expire")

    def test_EPN_template(self, cleanupmail):
        """Modify the template to ensure changes are applied.
        """
        exp_msg = textwrap.dedent('''
            Hi {{ first }} {{last}},
            Your login entry {{uid}} is going to expire on
            {{ expiration }}. Please change it soon.

            Your friendly neighborhood admins.
        ''')
        self.master.put_file_contents('/etc/ipa/epn/expire_msg.template',
                                      exp_msg)

        tasks.ipa_epn(self.master)
        for i in self.notify_ttls:
            validate_mail(self.master, i,
                          "Hi test user,\nYour login entry user%d is going" % i)

    def test_mailtest(self, cleanupmail):
        """Execute mailtest to validate mail is working

           Set of of our pre-created users as the smtp_admin to receive
           the mail, run ipa-epn --mailtest, then validate the result.

           Using a non-expired user here, user2, to receive the result.
        """
        epn_conf = (
            USER_EPN_CONF
            + textwrap.dedent(
                """\
                smtp_admin=user2@{domain}
                """
            )
        ).format(
            user=self.master.config.admin_name,
            password=self.master.config.admin_password,
            domain=self.master.domain.name,
        )
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)

        tasks.ipa_epn(self.master, mailtest=True)
        validate_mail(self.master, 2,
                      "Hi SAMPLE USER,\nYour login entry SAUSER is going")

    def test_mailtest_dry_run(self):
        try:
            tasks.ipa_epn(self.master, mailtest=True, dry_run=True)
        except CalledProcessError as e:
            assert 'You cannot specify' in e.stderr
        else:
            raise AssertionError('--mail-test and --dry-run aren\'t supposed '
                                 'to succeed')

    def test_EPN_starttls(self, cleanupmail):
        """Configure with starttls and test delivery
        """
        epn_conf = STARTTLS_EPN_CONF.format(
            server=self.master.hostname,
            user=self.master.config.admin_name,
            password=self.master.config.admin_password,
        )
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)
        configure_starttls(self.master)

        tasks.ipa_epn(self.master)
        for i in self.notify_ttls:
            validate_mail(self.master, i,
                          "Hi test user,\nYour login entry user%d is going" % i)

    def test_EPN_ssl(self, cleanupmail):
        """Configure with ssl and test delivery
        """
        epn_conf = SSL_EPN_CONF.format(
            server=self.master.hostname,
            user=self.master.config.admin_name,
            password=self.master.config.admin_password,
        )
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)
        configure_ssl(self.master)

        tasks.ipa_epn(self.master)
        for i in self.notify_ttls:
            validate_mail(self.master, i,
                          "Hi test user,\nYour login entry user%d is going" % i)

    def test_EPN_delay_config(self, cleanupmail):
        """Test the smtp_delay configuration option
        """
        epn_conf = DEFAULT_EPN_CONF + textwrap.dedent(
            """\
            smtp_delay=A
            """
        )
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)

        result = tasks.ipa_epn(self.master, raiseonerr=False)
        assert "could not convert string to float: 'A'" in result.stderr_text

        epn_conf = DEFAULT_EPN_CONF + textwrap.dedent(
            """\
            smtp_delay=-1
            """
        )
        self.master.put_file_contents('/etc/ipa/epn.conf', epn_conf)
        result = tasks.ipa_epn(self.master, raiseonerr=False)
        assert "smtp_delay cannot be less than zero" in result.stderr_text

    def test_EPN_admin(self):
        """The admin user is special and has no givenName by default
           It also doesn't by default have an e-mail address
           Check --dry-run output.
        """
        self.master.put_file_contents('/etc/ipa/epn.conf', DEFAULT_EPN_CONF)
        self.master.run_command(
            ['ipa', 'user-mod', 'admin', '--password-expiration',
             datetime_to_generalized_time(
                 datetime.datetime.utcnow() + datetime.timedelta(days=7)
             )]
        )
        (unused, stderr_text, _unused) = self._check_epn_output(
            self.master, dry_run=True
        )
        assert "uid=admin" in stderr_text

    @pytest.mark.skip_if_platform(
        "debian", reason="Don't know how to download-only pkgs in Debian"
    )
    @pytest.mark.skip_if_platform(
        "altlinux", reason="Fedora/RHEL specific"
    )
    def test_EPN_reinstall(self):
        """Test that EPN can be installed, uninstalled and reinstalled.

           Since post-install we no longer have access to the repos
           the package is downloaded and stored prior to server
           installation.
        """
        tasks.uninstall_packages(self.clients[0], EPN_PKG)
        tasks.install_packages(self.clients[0],
                               [os.path.join('/tmp', self.pkg)])
        self.clients[0].run_command(r'rm -f /tmp/{}'.format(self.pkg))

        # re-installing will create a new epn.conf so any execution
        # of ipa-epn will verify the reinstall was ok. Since the previous
        # test would have failed this one should be ok with new config.

        # Re-run the admin user expected failure
        (unused, stderr_text, _unused) = self._check_epn_output(
            self.master, dry_run=True
        )
        assert "uid=admin" in stderr_text
