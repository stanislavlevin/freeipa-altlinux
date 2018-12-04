# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2014  Red Hat
# see file 'COPYING' for use and warranty information
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

"""
Tests for the `ipaserver.service` module.
"""

from __future__ import print_function
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipaserver.install import service
import pytest
import pwd
import os
import stat


@pytest.mark.tier0
def test_format_seconds():
    assert service.format_seconds(0) == '0 seconds'
    assert service.format_seconds(1) == '1 second'
    assert service.format_seconds(2) == '2 seconds'
    assert service.format_seconds(11) == '11 seconds'
    assert service.format_seconds(60) == '1 minute'
    assert service.format_seconds(61) == '1 minute 1 second'
    assert service.format_seconds(62) == '1 minute 2 seconds'
    assert service.format_seconds(120) == '2 minutes'
    assert service.format_seconds(125) == '2 minutes 5 seconds'

def assert_mod(actual_mod, expected_mod):
    """
    Compare the given permission sets
    """
    assert oct(actual_mod) == oct(expected_mod)

def assert_in_mod(mod, expected_bit):
    """
    Check whether an expected permission bit is within the given set
    """
    if not mod & expected_bit:
        raise AssertionError(
            "Permission set {0} doesn't contain expected {1}".format(
                oct(stat.S_IMODE(mod)), "{0:#06o}".format(expected_bit)
            )
        )


def assert_path(path, username):
    """
    Check whether the given user owns the given path
    """
    print("check for {}".format(path))
    user_pw = pwd.getpwnam(username)

    # check for symlink
    stats = os.lstat(path)
    mode = stats.st_mode
    if stat.S_ISLNK(mode):
        assert stats.st_uid == 0 or stats.st_uid == user_pw.pw_uid
        path = os.readlink(path)
        print("symlink found {}".format(path))
        if not path == "/":
            assert_path(path, username)
        return

    assert stat.S_ISDIR(mode)

    # path should be owned by either root or gssproxy user
    assert stats.st_uid == 0 or stats.st_uid == user_pw.pw_uid

    if stats.st_uid == user_pw.pw_uid:
        assert_in_mod(mode, stat.S_IXUSR)
        if not path == "/":
            assert_path(os.path.dirname(path), username)
        return

    if stats.st_gid == user_pw.pw_gid:
        assert_in_mod(mode, stat.S_IXGRP)
        if not path == "/":
            assert_path(os.path.dirname(path), username)
        return

    assert_in_mod(mode, stat.S_IXOTH)

    if not path == "/":
        assert_path(os.path.dirname(path), username)


def test_service_keytab_permissions():
    # HTTP service keytab
    username = constants.GSSPROXY_USER
    assert username
    http_keytab = paths.HTTP_KEYTAB
    assert http_keytab
    user_pw = pwd.getpwnam(username)

    stats = os.lstat(http_keytab)
    mode = stats.st_mode

    while stat.S_ISLNK(mode):
        assert stats.st_uid == 0 or stats.st_uid == user_pw.pw_uid
        http_keytab = os.readlink(http_keytab)
        print("httpd.keytab is symlink to {}".format(http_keytab))
        stats = os.lstat(http_keytab)
        mode = stats.st_mode

    assert stats.st_uid == user_pw.pw_uid
    assert stats.st_gid == user_pw.pw_gid

    assert stat.S_ISREG(mode)
    assert_mod(stat.S_IMODE(mode), 0o600)

    # each subdir of the full path should be accessible
    # as well as owned by root or gssproxy user
    assert_path(os.path.dirname(http_keytab), username)

    # a parent dir of keytab should be writable by our user
    stats = os.stat(os.path.dirname(http_keytab))
    mode = stats.st_mode

    assert stats.st_uid == 0
    assert stats.st_gid == user_pw.pw_gid

    assert stat.S_ISDIR(mode)

    if user_pw.pw_uid == 0:
        # by default gssproxy user is root
        expected_mod = 0o700
    else:
        # gssproxy user is non-privileged
        expected_mod = 0o770
    assert_mod(stat.S_IMODE(mode), expected_mod)
