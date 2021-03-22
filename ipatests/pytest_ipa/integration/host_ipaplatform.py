#
# Copyright (C) 2021  FreeIPA Contributors. See COPYING for license
#

"""Expose locally remote ipaplatform"""

import base64
import json
import textwrap


class HostPlatformNameSpace:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __getitem__(self, key):
        return self.__dict__[key]

    def __repr__(self):
        items = (f"{k}={v!r}" for k, v in self.__dict__.items())
        return "{}({})".format(type(self).__name__, ", ".join(items))


class HostPlatformPaths(HostPlatformNameSpace):
    pass


class HostPlatformOSInfo(HostPlatformNameSpace):
    pass


class HostPlatformConstants(HostPlatformNameSpace):
    pass


class HostPlatformKnownservices(HostPlatformNameSpace):
    pass


class HostIPAPlatform:
    """Expose locally remote ipaplatform"""

    def __init__(self, run_command):
        self.run_command = run_command
        self._paths = None
        self._constants = None
        self._knownservices = None
        self._osinfo = None

    @property
    def paths(self):
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
    def constants(self):
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
    def osinfo(self):
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
    def knownservices(self):
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
                json_data, object_hook=lambda x: HostPlatformKnownservices(**x)
            )

        return self._knownservices
