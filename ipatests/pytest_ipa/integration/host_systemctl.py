#
# Copyright (C) 2021  FreeIPA Contributors. See COPYING for license
#

"""Wrapper for systemctl to be run on remote host"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, List, Optional
    from pytest_multihost.transport import SSHCommand
    from .host import Host
    from ._types import HostPlatformService


class HostSystemctl:
    """Wrapper for systemctl to be run on remote host"""

    def __init__(self, host: Host) -> None:
        self.host = host

    def resolve_name(self, unit: str) -> str:
        knownservices = self.host.ipaplatform.knownservices
        knownservice: Optional[HostPlatformService] = knownservices.get(
            unit
        )  # type: ignore[assignment]
        if knownservice is None:
            raise ValueError(
                f"Cannot resolve remote service: '{unit}'",
                knownservices,
            )

        name = knownservice.systemd_name
        if unit == "dirsrv":
            # assume valid template name
            parts = name.split("@")
            if parts[1] == ".service":
                name = f"{parts[0]}@{self.host.ds_serverid}{parts[1]}"

        return name

    def run(
        self,
        systemctl_args: List[str],
        *,
        unit: str,
        resolve: bool = True,
        **kwargs: Any,
    ) -> SSHCommand:
        name = unit
        if resolve:
            name = self.resolve_name(unit)

        cmd = [self.host.ipaplatform.paths.SYSTEMCTL]
        cmd.extend(systemctl_args)
        cmd.append(name)
        return self.host.run_command(cmd, **kwargs)

    def start(self, unit: str, resolve: bool = True) -> None:
        self.run(["start"], unit=unit, resolve=resolve)

    def stop(self, unit: str, resolve: bool = True) -> None:
        self.run(["stop"], unit=unit, resolve=resolve)

    def reload(self, unit: str, resolve: bool = True) -> None:
        self.run(["reload"], unit=unit, resolve=resolve)

    def restart(self, unit: str, resolve: bool = True) -> None:
        self.run(["restart"], unit=unit, resolve=resolve)

    def try_restart(self, unit: str, resolve: bool = True) -> None:
        self.run(["try-restart"], unit=unit, resolve=resolve)

    def reload_or_restart(self, unit: str, resolve: bool = True) -> None:
        self.run(["reload-or-restart"], unit=unit, resolve=resolve)

    def try_reload_or_restart(self, unit: str, resolve: bool = True) -> None:
        self.run(
            ["try-reload-or-restart"],
            unit=unit,
            resolve=resolve,
        )

    def is_active(self, unit: str, resolve: bool = True) -> bool:
        result = self.run(
            ["is-active"], unit=unit, resolve=resolve, raiseonerr=False
        )
        return result.returncode == 0

    def is_failed(self, unit: str, resolve: bool = True) -> bool:
        result = self.run(
            ["is-failed"], unit=unit, resolve=resolve, raiseonerr=False
        )
        return result.returncode == 0

    def enable(
        self, unit: str, now: bool = False, resolve: bool = True
    ) -> None:
        args = ["enable"]
        if now:
            args.extend(["--now"])

        self.run(args, unit=unit, resolve=resolve)

    def disable(
        self, unit: str, now: bool = False, resolve: bool = True
    ) -> None:
        args = ["disable"]
        if now:
            args.extend(["--now"])

        self.run(args, unit=unit, resolve=resolve)

    def is_enabled(self, unit: str, resolve: bool = True) -> bool:
        result = self.run(
            ["is-enabled"], unit=unit, resolve=resolve, raiseonerr=False
        )
        return result.returncode == 0

    def mask(self, unit: str, now: bool = False, resolve: bool = True) -> None:
        args = ["mask"]
        if now:
            args.extend(["--now"])

        self.run(args, unit=unit, resolve=resolve)

    def unmask(self, unit: str, resolve: bool = True) -> None:
        self.run(["unmask"], unit=unit, resolve=resolve)

    def status(
        self, unit: str, resolve: bool = True, raiseonerr: bool = True
    ) -> str:
        res = self.run(
            ["status"],
            unit=unit,
            resolve=resolve,
            raiseonerr=raiseonerr,
        )
        return res.stdout_text
