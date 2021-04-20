#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#

"""Generate the value of MYPYPATH env variable

Most of the Python packages don't annotate their code,
but there are packages which mark code as type-annotated.

The problem is that OS distributions may have or may not
yet have annotated Python packages. For not yet annotated
in downstream Python packages the standalone stub files
can be generated. For example, using mypy's stubgen tool:

    stubgen --include-private -v $PKG_PATH -o stubs

"""
import os

from pkg_resources import get_distribution, parse_version

STUBS_PATH = "stubs"

ANNOTATED_DISTRS = (
    ("pytest", parse_version("6.2.3")),
    ("cryptography", parse_version("3.4.5")),
    ("pytest_multihost", None),
)


not_yet_annotated_distrs = [
    os.path.join(STUBS_PATH, distr)
    for distr, min_version in ANNOTATED_DISTRS
    if min_version is None
    or get_distribution(distr).parsed_version < min_version
]

print(os.pathsep.join(not_yet_annotated_distrs))
