#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

'''
This module contains ALT Linux specific platform files.
'''

import sys
import warnings

NAME = 'altlinux'

if sys.version_info < (3, 6):
    warnings.warn(
        "Support for Python 2.7 and 3.5 is deprecated. Python version "
        "3.6 or newer will be required in the next major release.",
        category=DeprecationWarning
    )
