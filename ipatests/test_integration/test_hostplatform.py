#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#
from __future__ import annotations

import os
import textwrap

import pytest

from ipatests.pytest_ipa.integration.tasks import FileBackup
from ipatests.test_integration.base import IntegrationTest


OS_RELEASE_TEST_DATA = textwrap.dedent(
    """\
        NAME="Test Platform"
        VERSION="1"
        ID=testplatform
        ID_LIKE="foo bar"
        VERSION_ID="1.2"
    """
)

PATHS_CODE = textwrap.dedent(
    """\
        from ipaplatform.base.paths import BasePathNamespace


        class TestplatformPathsNamespace(BasePathNamespace):
            STR_P = "/foo/bar"
            INT_P = 1
            BOOL_P = True
            NONE_P = None
            LIST_P = ["foo", "bar"]
            TUPLE_P = ("foo", "bar")
            DICT_P = {"foo": "bar"}

            OBJ_P = object()
            def foo(self):
                pass

        paths = TestplatformPathsNamespace()
    """
)

CONSTANTS_CODE = textwrap.dedent(
    """\
        from ipaplatform.base.constants import (
            BaseConstantsNamespace,
            User,
            Group,
        )


        class TestplatformConstantsNamespace(BaseConstantsNamespace):
            STR_C = "/foo/bar"
            INT_C = 1
            BOOL_C = True
            NONE_C = None
            LIST_C = ["foo", "bar"]
            TUPLE_C = ("foo", "bar")
            DICT_C = {"foo": "bar"}

            USER_C = User("_someuser")
            GROUP_C = Group("_somegroup")

            OBJ_C = object()
            def foo(self):
                pass

        constants = TestplatformConstantsNamespace()
    """
)

TASKS_CODE = textwrap.dedent(
    """\
        from ipaplatform.redhat.tasks import RedHatTaskNamespace


        class TestplatformTaskNamespace(RedHatTaskNamespace):
            pass

        tasks = TestplatformTaskNamespace()
    """
)

SERVICES_CODE = textwrap.dedent(
    """\
        from ipaplatform.redhat import services as rh_services


        testplatform_system_units = rh_services.redhat_system_units.copy()
        testplatform_system_units = {"ipa": "foo-bar.service"}

        def testplatform_service_class_factory(name, api=None):
            if name in ["ipa"]:
                return TestplatformService(name, api)
            return rh_services.redhat_service_class_factory(name, api)


        class TestplatformService(rh_services.RedHatService):
            system_units = testplatform_system_units


        class TestplatformServices(rh_services.RedHatServices):
            def service_class_factory(self, name, api=None):
                return testplatform_service_class_factory(name, api)

        knownservices = TestplatformServices()
    """
)


@pytest.fixture(scope="class")
def remote_ipaplatform(request):
    """Prepare custom ipaplatform on remote host"""
    client = request.cls.replicas[0]
    test_platform = "testplatform"
    os_release = "/etc/os-release"

    result = client.run_command(
        [
            "python3",
            "-c",
            textwrap.dedent(
                """\
                    import os

                    import ipaplatform


                    print(os.path.dirname(ipaplatform.__file__))
                """
            ),
        ]
    )
    ipaplatform_path = result.stdout_text.rstrip()
    platform_path = os.path.join(ipaplatform_path, test_platform)
    override_path = os.path.join(ipaplatform_path, "override.py")
    paths_path = os.path.join(platform_path, "paths.py")
    constants_path = os.path.join(platform_path, "constants.py")
    tasks_path = os.path.join(platform_path, "tasks.py")
    services_path = os.path.join(platform_path, "services.py")

    with FileBackup(client, os_release):
        client.put_file_contents(os_release, OS_RELEASE_TEST_DATA)
        client.run_command(["mkdir", platform_path])

        with FileBackup(client, override_path):
            client.put_file_contents(
                override_path, f"OVERRIDE = '{test_platform}'"
            )
            client.put_file_contents(paths_path, PATHS_CODE)
            client.put_file_contents(constants_path, CONSTANTS_CODE)
            client.put_file_contents(tasks_path, TASKS_CODE)
            client.put_file_contents(services_path, SERVICES_CODE)
            yield
            client.run_command(["rm", "-rf", platform_path])


@pytest.mark.usefixtures("remote_ipaplatform")
class TestHostPlatform(IntegrationTest):
    """Tests for remote IPA platform

    0) Install nothing
    1) Create remote test os-release
    2) Create remote test ipaplatform
    3) Override remote ipaplatform
    4) Verify remote paths
    5) Verify remote constants
    6) Verify remote osinfo
    7) Verify remote knownservices
    """

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        # make_class_logs caches actual platform not the test one
        cls.replicas[0].invalidate_ipaplatform()

    @classmethod
    def uninstall(cls, mh):
        pass

    def test_paths_attrs(self):
        hp = self.replicas[0].ipaplatform.paths

        # pylint: disable=no-member
        assert hp.STR_P == "/foo/bar", hp  # type: ignore[attr-defined]
        assert hp.INT_P == 1, hp  # type: ignore[attr-defined]
        assert hp.BOOL_P is True, hp  # type: ignore[attr-defined]
        assert hp.NONE_P is None, hp  # type: ignore[attr-defined]
        assert hp.LIST_P == ["foo", "bar"], hp  # type: ignore[attr-defined]
        assert hp.TUPLE_P == ["foo", "bar"], hp  # type: ignore[attr-defined]
        assert hp.DICT_P == {"foo": "bar"}, hp  # type: ignore[attr-defined]

        with pytest.raises(AttributeError):
            assert hp.OBJ_P == "something"  # type: ignore[attr-defined]

        with pytest.raises(AttributeError):
            assert hp.foo == "something"  # type: ignore[attr-defined]
        # pylint: enable=no-member

    def test_constants_attrs(self):
        hc = self.replicas[0].ipaplatform.constants
        # pylint: disable=no-member
        assert hc.STR_C == "/foo/bar", hc  # type: ignore[attr-defined]
        assert hc.INT_C == 1, hc  # type: ignore[attr-defined]
        assert hc.BOOL_C is True, hc  # type: ignore[attr-defined]
        assert hc.NONE_C is None, hc  # type: ignore[attr-defined]
        assert hc.LIST_C == ["foo", "bar"], hc  # type: ignore[attr-defined]
        assert hc.TUPLE_C == ["foo", "bar"], hc  # type: ignore[attr-defined]
        assert hc.DICT_C == {"foo": "bar"}, hc  # type: ignore[attr-defined]

        assert hc.USER_C == "_someuser", hc  # type: ignore[attr-defined]
        assert hc.GROUP_C == "_somegroup", hc  # type: ignore[attr-defined]

        with pytest.raises(AttributeError):
            assert hc.OBJ_C == "something"  # type: ignore[attr-defined]

        with pytest.raises(AttributeError):
            assert hc.foo == "something"  # type: ignore[attr-defined]
        # pylint: enable=no-member

    def test_osinfo_attrs(self):
        host_osinfo = self.replicas[0].ipaplatform.osinfo
        # pylint: disable=no-member
        assert host_osinfo.name == "Test Platform", host_osinfo
        assert host_osinfo.id == "testplatform", host_osinfo
        assert host_osinfo.id_like == ["foo", "bar"], host_osinfo
        assert host_osinfo.version == "1", host_osinfo
        assert host_osinfo.version_number == [1, 2], host_osinfo
        assert host_osinfo.platform == "testplatform", host_osinfo
        # pylint: enable=no-member

    def test_knownservices_attrs(self):
        host_knownservices = self.replicas[0].ipaplatform.knownservices
        # pylint: disable=no-member
        test_service = host_knownservices["ipa"]
        assert test_service.service_name == "ipa", host_knownservices
        assert (
            test_service.systemd_name == "foo-bar.service"
        ), host_knownservices
        # pylint: enable=no-member
