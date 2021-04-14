#
# Copyright (C) 2021  FreeIPA Contributors. See COPYING for license
#
from __future__ import annotations

"""Expose locally remote ipaplatform"""

import base64
import json
import textwrap

from .host_namespaces import (
    HostPlatformPaths,
    HostPlatformOSInfo,
    HostPlatformConstants,
    HostPlatformKnownservices,
)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional, Tuple
    from ipatests.pytest_ipa.integration._types import RunCommandCb


class HostPlatformTasks:
    def __init__(self, run_command: RunCommandCb) -> None:
        self.run_command = run_command
        self._get_pkcs11_modules: Optional[Tuple[str, ...]] = None

    def get_pkcs11_modules(self) -> Tuple[str, ...]:
        if self._get_pkcs11_modules is None:
            code = textwrap.dedent(
                """\
                    import base64
                    import json

                    from ipaplatform.tasks import tasks


                    pkcs11_modules = tasks.get_pkcs11_modules()
                    json_data = json.dumps(pkcs11_modules)
                    json_base64 = base64.b64encode(
                        json_data.encode("utf-8")
                    ).decode("ascii")
                    print(json_base64)
                """
            )
            cmd = ["python3", "-c", code]
            res = self.run_command(cmd, log_stdout=False)
            json_data = base64.b64decode(res.stdout_bytes).decode("utf-8")
            self._get_pkcs11_modules = json.loads(json_data)

        return self._get_pkcs11_modules


class HostIPAPlatform:
    """Expose locally remote ipaplatform"""

    def __init__(self, run_command: RunCommandCb) -> None:
        self.run_command = run_command
        self._paths: Optional[HostPlatformPaths] = None
        self._constants: Optional[HostPlatformConstants] = None
        self._knownservices: Optional[HostPlatformKnownservices] = None
        self._osinfo: Optional[HostPlatformOSInfo] = None
        self._tasks: Optional[HostPlatformTasks] = None

    @property
    def paths(self) -> HostPlatformPaths:
        if self._paths is None:
            code = textwrap.dedent(
                """\
                    import base64
                    import json

                    from ipaplatform.paths import paths


                    remote_paths = {}
                    for name in sorted(dir(paths)):
                        if name.startswith("_"):
                            continue

                        value = getattr(paths, name)
                        try:
                            json.dumps(value)
                        except TypeError:
                            continue

                        remote_paths[name] = value

                    json_data = json.dumps(remote_paths)
                    json_base64 = base64.b64encode(
                        json_data.encode("utf-8")
                    ).decode("ascii")
                    print(json_base64)
                """
            )
            cmd = ["python3", "-c", code]
            res = self.run_command(cmd, log_stdout=False)
            json_data = base64.b64decode(res.stdout_bytes).decode("utf-8")
            self._paths = HostPlatformPaths(**json.loads(json_data))

        return self._paths

    @property
    def constants(self) -> HostPlatformConstants:
        if self._constants is None:
            code = textwrap.dedent(
                """\
                    import base64
                    import json
                    from ipaplatform.constants import constants


                    remote_constants = {}
                    for name in sorted(dir(constants)):
                        if name.startswith("_"):
                            continue

                        value = getattr(constants, name)
                        try:
                            json.dumps(value)
                        except TypeError:
                            continue

                        remote_constants[name] = value

                    json_data = json.dumps(remote_constants)
                    json_base64 = base64.b64encode(
                        json_data.encode("utf-8")
                    ).decode("ascii")
                    print(json_base64)
                """
            )
            cmd = ["python3", "-c", code]
            res = self.run_command(cmd, log_stdout=False)
            json_data = base64.b64decode(res.stdout_bytes).decode("utf-8")
            self._constants = HostPlatformConstants(**json.loads(json_data))

        return self._constants

    @property
    def osinfo(self) -> HostPlatformOSInfo:
        if self._osinfo is None:
            code = textwrap.dedent(
                """\
                    import base64
                    import json

                    from ipaplatform.osinfo import osinfo


                    remote_osinfo = {}
                    for name in sorted(dir(osinfo)):
                        if name.startswith("_"):
                            continue

                        value = getattr(osinfo, name)
                        try:
                            json.dumps(value)
                        except TypeError:
                            continue

                        remote_osinfo[name] = value

                    json_data = json.dumps(remote_osinfo)
                    json_base64 = base64.b64encode(
                        json_data.encode("utf-8")
                    ).decode("ascii")
                    print(json_base64)
                """
            )
            cmd = ["python3", "-c", code]
            res = self.run_command(cmd, log_stdout=False)
            json_data = base64.b64decode(res.stdout_bytes).decode("utf-8")
            self._osinfo = HostPlatformOSInfo(**json.loads(json_data))

        return self._osinfo

    @property
    def knownservices(self) -> HostPlatformKnownservices:
        if self._knownservices is None:
            code = textwrap.dedent(
                """\
                    import base64
                    import json

                    from ipaplatform.services import knownservices


                    remote_knownservices = {}
                    for k,v in knownservices.items():
                        remote_knownservices[k] = {}

                        for name in sorted(dir(v)):
                            if name.startswith("_"):
                                continue

                            value = getattr(v, name)
                            try:
                                json.dumps(value)
                            except TypeError:
                                continue

                            remote_knownservices[k][name] = value

                    json_data = json.dumps(remote_knownservices)
                    json_base64 = base64.b64encode(
                        json_data.encode("utf-8")
                    ).decode("ascii")
                    print(json_base64)
                """
            )
            cmd = ["python3", "-c", code]
            res = self.run_command(cmd, log_stdout=False)
            json_data = base64.b64decode(res.stdout_bytes).decode("utf-8")
            self._knownservices = json.loads(
                json_data,
                object_hook=lambda x: (
                    HostPlatformKnownservices(**x)  # type: ignore[misc]
                ),
            )

        return self._knownservices

    @property
    def tasks(self) -> HostPlatformTasks:
        if self._tasks is None:
            self._tasks = HostPlatformTasks(self.run_command)
        return self._tasks
