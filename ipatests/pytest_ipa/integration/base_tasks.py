#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#
"""Common tasks"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional
    from .host import Host


def create_temp_file(
    host: Host, directory: Optional[str] = None, create_file: bool = True
) -> str:
    """Creates temporary file using mktemp."""
    cmd = ['mktemp']
    if create_file is False:
        cmd += ['--dry-run']
    if directory is not None:
        cmd += ['-p', directory]
    return host.run_command(cmd).stdout_text.strip()
